//! Types et logique pure partagés entre l'interface (wasm) et le backend Tauri :
//! algorithmes, rapport de hachage et analyse des checksums collés ou lus dans
//! des fichiers `.sha256` / `SHA256SUMS`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algo {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Algo {
    pub const ALL: [Algo; 5] = [Algo::Md5, Algo::Sha1, Algo::Sha256, Algo::Sha384, Algo::Sha512];

    pub fn label(self) -> &'static str {
        match self {
            Algo::Md5 => "MD5",
            Algo::Sha1 => "SHA-1",
            Algo::Sha256 => "SHA-256",
            Algo::Sha384 => "SHA-384",
            Algo::Sha512 => "SHA-512",
        }
    }

    /// Longueur de l'empreinte en caractères hexadécimaux.
    pub fn hex_len(self) -> usize {
        match self {
            Algo::Md5 => 32,
            Algo::Sha1 => 40,
            Algo::Sha256 => 64,
            Algo::Sha384 => 96,
            Algo::Sha512 => 128,
        }
    }

    pub fn from_hex_len(len: usize) -> Option<Algo> {
        Algo::ALL.into_iter().find(|a| a.hex_len() == len)
    }

    /// Reconnaît `sha256`, `SHA-256`, `Sha_256`, `md5`… (insensible à la casse).
    pub fn from_name(name: &str) -> Option<Algo> {
        let n: String = name.chars().filter(|c| *c != '-' && *c != '_').collect::<String>().to_ascii_lowercase();
        match n.as_str() {
            "md5" => Some(Algo::Md5),
            "sha1" => Some(Algo::Sha1),
            "sha256" => Some(Algo::Sha256),
            "sha384" => Some(Algo::Sha384),
            "sha512" => Some(Algo::Sha512),
            _ => None,
        }
    }
}

/// Empreintes (hexadécimal minuscule) calculées en une seule passe.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha384: String,
    pub sha512: String,
}

impl Hashes {
    pub fn get(&self, algo: Algo) -> &str {
        match algo {
            Algo::Md5 => &self.md5,
            Algo::Sha1 => &self.sha1,
            Algo::Sha256 => &self.sha256,
            Algo::Sha384 => &self.sha384,
            Algo::Sha512 => &self.sha512,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReport {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub elapsed_ms: u64,
    pub hashes: Hashes,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
}

/// Checksum trouvé à côté du fichier (`fichier.iso.sha256`, `SHA256SUMS`…).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sidecar {
    /// Nom du fichier de checksums.
    pub source: String,
    /// Chemin complet du fichier de checksums (pour vérifier sa signature).
    pub path: String,
    pub hash: String,
}

/// Clé publique OpenPGP du trousseau de l'application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Empreinte complète, hexadécimal majuscule.
    pub fingerprint: String,
    /// Identifiant court (16 derniers caractères hexadécimaux de l'empreinte).
    pub key_id: String,
    pub user_ids: Vec<String>,
    /// Secondes Unix.
    pub created: Option<u64>,
    pub expires: Option<u64>,
    pub revoked: bool,
}

/// Résultat de la vérification OpenPGP d'un fichier de checksums.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureStatus {
    /// Aucune signature trouvée à côté du fichier.
    Absent,
    /// Signature cryptographiquement valide, faite par une clé du trousseau.
    Valid {
        key: KeyInfo,
        signed_at: Option<u64>,
        /// La clé avait déjà expiré à la date de la signature.
        key_expired: bool,
    },
    /// Signature présente, mais la clé du signataire n'est pas dans le trousseau.
    UnknownKey { issuer: String },
    /// Signature illisible, ne correspondant pas au contenu, ou faite par une clé révoquée.
    Invalid { reason: InvalidReason },
}

/// Motif d'un refus de signature. Les messages sont rédigés par l'interface, dans la langue
/// choisie ; `detail` ne contient que le texte technique brut (erreur système ou de bibliothèque).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidReason {
    /// Le contenu ne correspond pas à la signature.
    ContentMismatch,
    KeyRevoked {
        key_id: String,
    },
    /// Message signé en clair illisible, ou texte hors du bloc signé.
    MalformedCleartext,
    NotUtf8,
    TooLarge,
    SignatureUnreadable {
        detail: String,
    },
    ReadFailed {
        detail: String,
    },
}

/// Langue de l'interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    Fr,
    En,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::Fr, Lang::En];

    /// Balise BCP 47 courte (`fr`, `en`).
    pub fn tag(self) -> &'static str {
        match self {
            Lang::Fr => "fr",
            Lang::En => "en",
        }
    }

    /// Reconnaît `fr`, `fr-FR`, `FR_ca`, `en-US`… ; `None` pour les autres langues.
    pub fn from_tag(tag: &str) -> Option<Lang> {
        let primary = tag.trim().split(['-', '_']).next()?.to_ascii_lowercase();
        match primary.as_str() {
            "fr" => Some(Lang::Fr),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    /// Langue de l'interface pour une balise de navigateur ou du système : français si
    /// elle l'est, anglais sinon.
    pub fn detect(tag: &str) -> Lang {
        Lang::from_tag(tag).unwrap_or(Lang::En)
    }
}

/// Erreur d'une commande du backend. Sérialisée telle quelle vers l'interface, qui la traduit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppError {
    /// Un calcul a été remplacé par un autre ou annulé : pas une erreur à afficher.
    Cancelled,
    NotAFile,
    Io {
        detail: String,
    },
    KeyNotPublic {
        detail: String,
    },
    KeyUnreadable {
        detail: String,
    },
    KeyBindingInvalid {
        detail: String,
    },
    NoPublicKey,
    KeyFileTooLarge,
    KeyringWrite {
        detail: String,
    },
    KeyExport {
        detail: String,
    },
    InvalidFingerprint,
    ShellUnsupported,
    Internal {
        detail: String,
    },
}

/// Vrai si une clé expirant à `expires` était déjà expirée à `signed_at` (secondes Unix).
pub fn expired_at(expires: Option<u64>, signed_at: u64) -> bool {
    expires.is_some_and(|e| signed_at >= e)
}

/// Une ligne de checksum analysée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub algo: Option<Algo>,
    pub hash: String,
    pub file: Option<String>,
}

/// Empreinte attendue, avec l'algorithme déduit de sa longueur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub algo: Algo,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    Invalid,
}

/// Valide une empreinte hexadécimale et la met en minuscules.
fn clean_hash(token: &str, hint: Option<Algo>) -> Option<(Algo, String)> {
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let algo = Algo::from_hex_len(token.len())?;
    if hint.is_some_and(|h| h != algo) {
        return None;
    }
    Some((algo, token.to_ascii_lowercase()))
}

fn clean_file_name(raw: &str) -> Option<String> {
    let name = raw.trim().trim_start_matches('*').trim_start_matches("./");
    (!name.is_empty()).then(|| name.to_string())
}

/// Analyse une ligne de checksum. Formats reconnus :
/// `hash`, `hash  fichier`, `hash *fichier`, `sha256:hash`, `SHA256 (fichier) = hash`.
pub fn parse_line(line: &str) -> Option<Entry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }

    // Format BSD : ALGO (fichier) = hash
    if let (Some(open), Some(close)) = (line.find(" ("), line.rfind(") = ")) {
        if open < close {
            let hint = Algo::from_name(&line[..open]);
            let file = clean_file_name(&line[open + 2..close]);
            let token = line[close + 4..].trim();
            if let Some((_, hash)) = clean_hash(token, hint) {
                return Some(Entry { algo: hint, hash, file });
            }
        }
    }

    // Préfixe d'algorithme : sha256:hash ou sha256=hash
    if let Some(sep) = line.find([':', '=']) {
        if let Some(hint) = Algo::from_name(&line[..sep]) {
            let rest = line[sep + 1..].trim();
            let mut parts = rest.splitn(2, char::is_whitespace);
            let token = parts.next().unwrap_or("");
            let file = parts.next().and_then(clean_file_name);
            return clean_hash(token, Some(hint)).map(|(_, hash)| Entry { algo: Some(hint), hash, file });
        }
    }

    // Format coreutils : hash  fichier
    let mut parts = line.splitn(2, char::is_whitespace);
    let token = parts.next().unwrap_or("");
    let file = parts.next().and_then(clean_file_name);
    clean_hash(token, None).map(|(_, hash)| Entry { algo: None, hash, file })
}

/// Analyse une empreinte attendue collée par l'utilisateur. Accepte aussi les
/// empreintes découpées par des espaces ou des deux-points (`certutil`, `openssl`).
pub fn parse_expected(input: &str) -> Result<Expected, ParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ParseError::Empty);
    }
    if let Some(entry) = input.lines().find_map(parse_line) {
        let algo = Algo::from_hex_len(entry.hash.len()).ok_or(ParseError::Invalid)?;
        return Ok(Expected { algo, hash: entry.hash });
    }
    let compact: String = input.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    clean_hash(&compact, None).map(|(algo, hash)| Expected { algo, hash }).ok_or(ParseError::Invalid)
}

/// Cherche l'empreinte de `file_name` dans le contenu d'un fichier de checksums.
/// Avec `lenient`, la première entrée valide est acceptée même si le nom diffère
/// (cas d'un `fichier.sha256` dont l'appariement se fait par le nom du fichier).
pub fn find_entry(content: &str, file_name: &str, lenient: bool) -> Option<Entry> {
    let entries: Vec<Entry> = content.lines().filter_map(parse_line).collect();
    entries
        .iter()
        .find(|e| e.file.as_deref().is_some_and(|f| f.eq_ignore_ascii_case(file_name)))
        .or_else(|| entries.iter().find(|e| e.file.is_none() || (lenient && entries.len() == 1)))
        .cloned()
}

pub fn matches(expected: &Expected, hashes: &Hashes) -> bool {
    hashes.get(expected.algo) == expected.hash
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const MD5_ABC: &str = "900150983cd24fb0d6963f7d28e17f72";

    #[test]
    fn detects_algo_from_length() {
        for a in Algo::ALL {
            assert_eq!(Algo::from_hex_len(a.hex_len()), Some(a));
        }
        assert_eq!(Algo::from_hex_len(10), None);
    }

    #[test]
    fn parses_plain_and_uppercase() {
        let e = parse_expected(&SHA256_ABC.to_uppercase()).unwrap();
        assert_eq!(e.algo, Algo::Sha256);
        assert_eq!(e.hash, SHA256_ABC);
    }

    #[test]
    fn parses_coreutils_line() {
        let line = format!("{MD5_ABC} *abc.bin");
        let entry = parse_line(&line).unwrap();
        assert_eq!(entry.hash, MD5_ABC);
        assert_eq!(entry.file.as_deref(), Some("abc.bin"));
    }

    #[test]
    fn parses_prefixed_and_bsd() {
        let e = parse_expected(&format!("sha256:{SHA256_ABC}")).unwrap();
        assert_eq!(e.algo, Algo::Sha256);
        let e = parse_expected(&format!("SHA256 (abc.bin) = {SHA256_ABC}")).unwrap();
        assert_eq!(e.hash, SHA256_ABC);
        // le préfixe doit correspondre à la longueur
        assert!(parse_expected(&format!("md5:{SHA256_ABC}")).is_err());
    }

    #[test]
    fn parses_spaced_certutil_output() {
        let spaced: Vec<String> =
            SHA256_ABC.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
        let e = parse_expected(&spaced.join(" ")).unwrap();
        assert_eq!(e.hash, SHA256_ABC);
        let colons = spaced.join(":");
        assert_eq!(parse_expected(&colons).unwrap().hash, SHA256_ABC);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_expected("   "), Err(ParseError::Empty));
        assert_eq!(parse_expected("pas un hash"), Err(ParseError::Invalid));
        assert_eq!(parse_expected("abc123"), Err(ParseError::Invalid));
        assert_eq!(parse_expected(&format!("{SHA256_ABC}zz")), Err(ParseError::Invalid));
    }

    #[test]
    fn finds_entry_in_sums_file() {
        let content = format!("# commentaire\n{MD5_ABC}  other.iso\n{SHA256_ABC}  abc.bin\n");
        let e = find_entry(&content, "ABC.bin", false).unwrap();
        assert_eq!(e.hash, SHA256_ABC);
        assert!(find_entry(&content, "missing.bin", false).is_none());
    }

    #[test]
    fn lenient_accepts_single_renamed_entry() {
        let content = format!("{SHA256_ABC}  original.iso\n");
        assert!(find_entry(&content, "renamed.iso", false).is_none());
        assert_eq!(find_entry(&content, "renamed.iso", true).unwrap().hash, SHA256_ABC);
    }

    #[test]
    fn key_expiry_is_relative_to_signature_time() {
        assert!(!expired_at(None, 1_000));
        assert!(!expired_at(Some(2_000), 1_999));
        assert!(expired_at(Some(2_000), 2_000));
        assert!(expired_at(Some(2_000), 5_000));
    }

    #[test]
    fn language_tags() {
        assert_eq!(Lang::from_tag("fr"), Some(Lang::Fr));
        assert_eq!(Lang::from_tag("fr-CA"), Some(Lang::Fr));
        assert_eq!(Lang::from_tag("EN_us"), Some(Lang::En));
        assert_eq!(Lang::from_tag("de-DE"), None);
        assert_eq!(Lang::from_tag(""), None);
        // Langue non prise en charge : anglais.
        assert_eq!(Lang::detect("de-DE"), Lang::En);
        assert_eq!(Lang::detect("fr-FR"), Lang::Fr);
        for lang in Lang::ALL {
            assert_eq!(Lang::from_tag(lang.tag()), Some(lang));
        }
    }

    #[test]
    fn compares_against_hashes() {
        let hashes = Hashes { sha256: SHA256_ABC.into(), ..Default::default() };
        let ok = Expected { algo: Algo::Sha256, hash: SHA256_ABC.into() };
        let ko = Expected { algo: Algo::Sha256, hash: "0".repeat(64) };
        assert!(matches(&ok, &hashes));
        assert!(!matches(&ko, &hashes));
    }
}
