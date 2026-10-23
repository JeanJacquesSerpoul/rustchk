//! Réputation d'un fichier auprès de MalwareBazaar (abuse.ch) et de VirusTotal.
//!
//! Désactivée par défaut. Seule l'empreinte SHA-256 est envoyée, jamais le fichier ni son nom ;
//! chaque service demande une clé d'API personnelle, rangée chiffrée (voir [`secret`]) dans
//! `reputation.json` à côté du trousseau.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use rustchk_core::{AppError, Lookup, LookupError, ReputationSettings, Service, ServiceReport};
use serde_json::Value;

use crate::secret;

const MALWAREBAZAAR_URL: &str = "https://mb-api.abuse.ch/api/v1/";
const VIRUSTOTAL_URL: &str = "https://www.virustotal.com/api/v3/files/";

/// Réglages persistants de l'analyse en ligne.
pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn new(path: PathBuf) -> Self {
        SettingsStore { path }
    }

    /// Réglages enregistrés, clés déchiffrées ; ceux par défaut (analyse désactivée) si le fichier manque
    /// ou est illisible. Une clé indéchiffrable (fichier copié depuis un autre compte) est vidée.
    pub fn load(&self) -> ReputationSettings {
        let stored: ReputationSettings =
            fs::read(&self.path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        let settings = ReputationSettings {
            enabled: stored.enabled,
            malwarebazaar_key: secret::open(&stored.malwarebazaar_key).unwrap_or_default(),
            virustotal_key: secret::open(&stored.virustotal_key).unwrap_or_default(),
        };
        // Clés en clair d'une version précédente : les chiffrer sans attendre le prochain enregistrement.
        if !secret::is_sealed(&stored.malwarebazaar_key) || !secret::is_sealed(&stored.virustotal_key) {
            let _ = self.save(&settings);
        }
        settings
    }

    pub fn save(&self, settings: &ReputationSettings) -> Result<(), AppError> {
        let write_error = |detail: String| AppError::SettingsWrite { detail };
        let sealed = |service| secret::seal(settings.key(service)).map_err(write_error);
        let stored = ReputationSettings {
            enabled: settings.enabled,
            malwarebazaar_key: sealed(Service::MalwareBazaar)?,
            virustotal_key: sealed(Service::VirusTotal)?,
        };
        let json = serde_json::to_vec_pretty(&stored).map_err(|e| write_error(e.to_string()))?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|e| write_error(e.to_string()))?;
        }
        fs::write(&self.path, json).map_err(|e| write_error(e.to_string()))
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        // Les codes 4xx portent l'information utile (empreinte inconnue, clé refusée, quota) : les lire.
        .http_status_as_error(false)
        .user_agent(concat!("RustChk/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn failed(error: LookupError) -> Lookup {
    Lookup::Failed { error }
}

fn unexpected(detail: impl Into<String>) -> Lookup {
    failed(LookupError::Unexpected { detail: detail.into() })
}

/// Interroge les services configurés, en parallèle. `sha256` doit avoir été validée.
pub fn check(settings: &ReputationSettings, sha256: &str) -> Vec<ServiceReport> {
    let agent = agent();
    std::thread::scope(|scope| {
        let jobs: Vec<_> = settings
            .services()
            .into_iter()
            .map(|service| {
                let (agent, key) = (&agent, settings.key(service));
                (service, scope.spawn(move || lookup(agent, service, key, sha256)))
            })
            .collect();
        jobs.into_iter()
            .map(|(service, job)| ServiceReport {
                service,
                lookup: job.join().unwrap_or_else(|_| unexpected("thread panicked")),
            })
            .collect()
    })
}

fn lookup(agent: &ureq::Agent, service: Service, key: &str, sha256: &str) -> Lookup {
    let response = match service {
        Service::MalwareBazaar => {
            agent.post(MALWAREBAZAAR_URL).header("Auth-Key", key).send_form([("query", "get_info"), ("hash", sha256)])
        }
        Service::VirusTotal => agent.get(format!("{VIRUSTOTAL_URL}{sha256}")).header("x-apikey", key).call(),
    };
    let mut response = match response {
        Ok(r) => r,
        Err(e) => return failed(LookupError::Network { detail: e.to_string() }),
    };
    let status = response.status().as_u16();
    let body = match response.body_mut().read_to_string() {
        Ok(b) => b,
        Err(e) => return failed(LookupError::Network { detail: e.to_string() }),
    };
    match service {
        Service::MalwareBazaar => parse_malwarebazaar(status, &body),
        Service::VirusTotal => parse_virustotal(status, &body),
    }
}

/// Réponse de `get_info` : `{"query_status": "ok", "data": [{"signature": …, "tags": […]}]}`.
fn parse_malwarebazaar(status: u16, body: &str) -> Lookup {
    let json: Option<Value> = serde_json::from_str(body).ok();
    let query_status = json.as_ref().and_then(|j| j["query_status"].as_str()).unwrap_or_default();
    match (status, query_status) {
        (401 | 403, _) | (_, "unknown_auth_key" | "no_api_key" | "user_blacklisted") => failed(LookupError::InvalidKey),
        (429, _) => failed(LookupError::RateLimited),
        (_, "hash_not_found") => Lookup::Unknown,
        (200, "ok") => {
            let sample = &json.as_ref().map(|j| j["data"][0].clone()).unwrap_or_default();
            let family = sample["signature"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
            let tags = sample["tags"]
                .as_array()
                .map(|tags| tags.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            Lookup::Listed { family, tags }
        }
        (_, "") => unexpected(format!("HTTP {status}")),
        (_, other) => unexpected(other),
    }
}

/// Objet fichier de l'API v3 : `data.attributes.last_analysis_stats` et le libellé de menace suggéré.
fn parse_virustotal(status: u16, body: &str) -> Lookup {
    let json: Value = serde_json::from_str(body).unwrap_or_default();
    match status {
        200 => {
            let attributes = &json["data"]["attributes"];
            let stats = &attributes["last_analysis_stats"];
            if !stats.is_object() {
                return unexpected("last_analysis_stats missing");
            }
            let count = |field: &str| stats[field].as_u64().unwrap_or(0) as u32;
            let (malicious, suspicious) = (count("malicious"), count("suspicious"));
            let engines = malicious + suspicious + count("harmless") + count("undetected");
            let label = attributes["popular_threat_classification"]["suggested_threat_label"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            Lookup::Scanned { malicious, suspicious, engines, label }
        }
        404 => Lookup::Unknown,
        401 | 403 => failed(LookupError::InvalidKey),
        429 => failed(LookupError::RateLimited),
        _ => unexpected(json["error"]["code"].as_str().map_or_else(|| format!("HTTP {status}"), str::to_string)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malwarebazaar_responses() {
        let listed = r#"{"query_status":"ok","data":[{"sha256_hash":"ab","signature":"LummaStealer","tags":["exe","stealer"]}]}"#;
        assert_eq!(
            parse_malwarebazaar(200, listed),
            Lookup::Listed { family: Some("LummaStealer".into()), tags: vec!["exe".into(), "stealer".into()] }
        );
        let no_family = r#"{"query_status":"ok","data":[{"signature":null,"tags":null}]}"#;
        assert_eq!(parse_malwarebazaar(200, no_family), Lookup::Listed { family: None, tags: vec![] });
        assert_eq!(parse_malwarebazaar(200, r#"{"query_status":"hash_not_found"}"#), Lookup::Unknown);
        assert_eq!(
            parse_malwarebazaar(401, r#"{"query_status":"unknown_auth_key"}"#),
            Lookup::Failed { error: LookupError::InvalidKey }
        );
        assert_eq!(parse_malwarebazaar(403, "Forbidden"), Lookup::Failed { error: LookupError::InvalidKey });
        assert_eq!(parse_malwarebazaar(429, ""), Lookup::Failed { error: LookupError::RateLimited });
        assert_eq!(
            parse_malwarebazaar(200, r#"{"query_status":"illegal_hash"}"#),
            Lookup::Failed { error: LookupError::Unexpected { detail: "illegal_hash".into() } }
        );
        assert_eq!(
            parse_malwarebazaar(502, "<html>"),
            Lookup::Failed { error: LookupError::Unexpected { detail: "HTTP 502".into() } }
        );
    }

    #[test]
    fn virustotal_responses() {
        let scanned = r#"{"data":{"attributes":{
            "last_analysis_stats":{"malicious":52,"suspicious":1,"undetected":14,"harmless":0,"timeout":0,"type-unsupported":5},
            "popular_threat_classification":{"suggested_threat_label":"trojan.redline/stealer"}}}}"#;
        assert_eq!(
            parse_virustotal(200, scanned),
            Lookup::Scanned { malicious: 52, suspicious: 1, engines: 67, label: Some("trojan.redline/stealer".into()) }
        );
        let clean = r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":60,"harmless":10}}}}"#;
        assert_eq!(
            parse_virustotal(200, clean),
            Lookup::Scanned { malicious: 0, suspicious: 0, engines: 70, label: None }
        );
        assert_eq!(parse_virustotal(404, r#"{"error":{"code":"NotFoundError"}}"#), Lookup::Unknown);
        assert_eq!(
            parse_virustotal(401, r#"{"error":{"code":"WrongCredentialsError"}}"#),
            Lookup::Failed { error: LookupError::InvalidKey }
        );
        assert_eq!(
            parse_virustotal(429, r#"{"error":{"code":"QuotaExceededError"}}"#),
            Lookup::Failed { error: LookupError::RateLimited }
        );
        assert_eq!(
            parse_virustotal(400, r#"{"error":{"code":"InvalidArgumentError"}}"#),
            Lookup::Failed { error: LookupError::Unexpected { detail: "InvalidArgumentError".into() } }
        );
        assert_eq!(
            parse_virustotal(200, "{}"),
            Lookup::Failed { error: LookupError::Unexpected { detail: "last_analysis_stats missing".into() } }
        );
    }

    #[test]
    fn settings_round_trip_and_trim_keys() {
        let dir = std::env::temp_dir().join(format!("rustchk-settings-{}", std::process::id()));
        let store = SettingsStore::new(dir.join("reputation.json"));
        assert_eq!(store.load(), ReputationSettings::default());
        let settings =
            ReputationSettings { enabled: true, malwarebazaar_key: " mb \n".into(), virustotal_key: String::new() };
        store.save(&settings).unwrap();
        let loaded = store.load();
        assert!(loaded.enabled);
        assert_eq!(loaded.malwarebazaar_key, "mb");
        assert_eq!(loaded.services(), vec![Service::MalwareBazaar]);
        // Analyse désactivée : rien n'est envoyé, même avec des clés.
        assert!(check(&ReputationSettings { enabled: false, ..loaded }, &"0".repeat(64)).is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn keys_are_encrypted_on_disk_and_plain_keys_migrated() {
        let dir = std::env::temp_dir().join(format!("rustchk-secret-{}", std::process::id()));
        let path = dir.join("reputation.json");
        let store = SettingsStore::new(path.clone());
        let settings = ReputationSettings {
            enabled: true,
            malwarebazaar_key: "mb-secret".into(),
            virustotal_key: "vt-secret".into(),
        };
        store.save(&settings).unwrap();
        let on_disk = fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.contains("mb-secret"), !cfg!(windows));
        assert_eq!(store.load(), settings);

        // Fichier d'une version précédente, clés en clair : chiffré dès la lecture.
        fs::write(&path, r#"{"enabled":true,"malwarebazaar_key":"mb-secret","virustotal_key":""}"#).unwrap();
        assert_eq!(store.load().malwarebazaar_key, "mb-secret");
        assert_eq!(fs::read_to_string(&path).unwrap().contains("mb-secret"), !cfg!(windows));
        assert_eq!(store.load().malwarebazaar_key, "mb-secret");

        // Clé chiffrée par un autre compte : vidée plutôt que d'envoyer n'importe quoi.
        fs::write(&path, r#"{"enabled":true,"malwarebazaar_key":"dpapi:00ff","virustotal_key":""}"#).unwrap();
        assert!(store.load().services().is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}
