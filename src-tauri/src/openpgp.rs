//! Authentification OpenPGP des fichiers de checksums (`SHA256SUMS` + `SHA256SUMS.gpg`/`.asc`/`.sig`,
//! ou fichier signé en clair) avec une implémentation OpenPGP en Rust pur ([rPGP](https://crates.io/crates/pgp)).
//!
//! Seules les clés explicitement importées dans le trousseau de l'application font foi :
//! aucune clé n'est récupérée sur le réseau ni lue « à côté » du téléchargement.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use pgp::composed::{ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey};
use pgp::packet::Signature;
use pgp::types::KeyDetails;
use rustchk_core::{expired_at, AppError, InvalidReason, KeyInfo, SignatureStatus};

use crate::sidecar::MAX_SIDECAR_BYTES;

/// Extensions de signature détachée essayées, dans l'ordre : `<fichier>.<ext>`.
const SIGNATURE_EXTENSIONS: [&str; 5] = ["asc", "sig", "gpg", "sign", "pgp"];

const CLEARSIGN_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// Vrai si `sig` annonce `key` comme émetteur (empreinte ou identifiant de clé).
fn issued_by(sig: &Signature, key: &impl KeyDetails) -> bool {
    let fingerprint = key.fingerprint();
    let key_id = key.legacy_key_id();
    sig.issuer_fingerprint().iter().any(|f| f.as_bytes() == fingerprint.as_bytes())
        || sig
            .issuer_key_id()
            .iter()
            .any(|k| AsRef::<[u8]>::as_ref(*k) == AsRef::<[u8]>::as_ref(&key_id))
}

fn issued_by_cert(sig: &Signature, cert: &SignedPublicKey) -> bool {
    issued_by(sig, cert) || cert.public_subkeys.iter().any(|sub| issued_by(sig, sub))
}

/// Vérifie `$check` (une expression `Result`) avec la clé primaire puis chaque sous-clé.
macro_rules! with_any_key {
    ($cert:expr, |$k:ident| $check:expr) => {{
        let cert: &SignedPublicKey = $cert;
        let primary_ok = {
            let $k = cert;
            $check.is_ok()
        };
        primary_ok
            || cert.public_subkeys.iter().any(|sub| {
                let $k = sub;
                $check.is_ok()
            })
    }};
}

/// Expiration de la clé : dernière auto-signature portant (ou non) une durée de validité.
fn key_expiration(key: &SignedPublicKey, created: u64) -> Option<u64> {
    key.details
        .users
        .iter()
        .flat_map(|u| u.signatures.iter())
        .chain(key.details.direct_signatures.iter())
        .filter(|s| issued_by(s, key))
        .filter_map(|s| Some((s.created()?.as_secs(), s.key_expiration_time().map(|d| d.as_secs()))))
        .max_by_key(|(created_at, _)| *created_at)
        .and_then(|(_, validity)| validity.filter(|d| *d > 0).map(|d| created + u64::from(d)))
}

pub fn key_info(key: &SignedPublicKey) -> KeyInfo {
    let fingerprint = hex_upper(key.fingerprint().as_bytes());
    let key_id = fingerprint[fingerprint.len().saturating_sub(16)..].to_string();
    let created = u64::from(key.created_at().as_secs());
    KeyInfo {
        key_id,
        user_ids: key
            .details
            .users
            .iter()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .collect(),
        created: Some(created),
        expires: key_expiration(key, created),
        revoked: !key.details.revocation_signatures.is_empty(),
        fingerprint,
    }
}

/// Lit une ou plusieurs clés publiques (binaires ou ASCII-armor) et contrôle leurs auto-signatures.
pub fn parse_public_keys(data: &[u8]) -> Result<Vec<SignedPublicKey>, AppError> {
    let (parsed, _) = SignedPublicKey::from_reader_many(Cursor::new(data.to_vec()))
        .map_err(|e| AppError::KeyNotPublic { detail: e.to_string() })?;
    let mut keys = Vec::new();
    for key in parsed {
        let key = key.map_err(|e| AppError::KeyUnreadable { detail: e.to_string() })?;
        key.verify_bindings()
            .map_err(|e| AppError::KeyBindingInvalid { detail: e.to_string() })?;
        keys.push(key);
    }
    if keys.is_empty() {
        return Err(AppError::NoPublicKey);
    }
    Ok(keys)
}

/// Trousseau persistant : un fichier `<EMPREINTE>.asc` par clé publique.
pub struct Keyring {
    dir: PathBuf,
}

impl Keyring {
    pub fn new(dir: PathBuf) -> Self {
        Keyring { dir }
    }

    fn path_for(&self, fingerprint: &str) -> PathBuf {
        self.dir.join(format!("{fingerprint}.asc"))
    }

    pub fn load(&self) -> Vec<SignedPublicKey> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "asc"))
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|bytes| parse_public_keys(&bytes).ok())
            .flatten()
            .collect()
    }

    pub fn list(&self) -> Vec<KeyInfo> {
        let mut infos: Vec<KeyInfo> = self.load().iter().map(key_info).collect();
        infos.sort_by(|a, b| a.user_ids.cmp(&b.user_ids).then(a.fingerprint.cmp(&b.fingerprint)));
        infos
    }

    pub fn import(&self, data: &[u8]) -> Result<Vec<KeyInfo>, AppError> {
        let write_error = |e: std::io::Error| AppError::KeyringWrite { detail: e.to_string() };
        let keys = parse_public_keys(data)?;
        fs::create_dir_all(&self.dir).map_err(write_error)?;
        let mut infos = Vec::new();
        for key in &keys {
            let info = key_info(key);
            let armored = key
                .to_armored_string(ArmorOptions::default())
                .map_err(|e| AppError::KeyExport { detail: e.to_string() })?;
            fs::write(self.path_for(&info.fingerprint), armored).map_err(write_error)?;
            infos.push(info);
        }
        Ok(infos)
    }

    pub fn remove(&self, fingerprint: &str) -> Result<(), AppError> {
        // L'empreinte devient un nom de fichier : on n'accepte que de l'hexadécimal.
        if fingerprint.is_empty() || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::InvalidFingerprint);
        }
        match fs::remove_file(self.path_for(&fingerprint.to_ascii_uppercase())) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(AppError::KeyringWrite { detail: e.to_string() })
            }
            _ => Ok(()),
        }
    }
}

fn is_clearsigned(content: &[u8]) -> bool {
    // `contains` et non `starts_with` : du texte forgé avant l'en-tête doit être rejeté, pas ignoré.
    String::from_utf8_lossy(content).contains(CLEARSIGN_HEADER)
}

/// Contenu *effectivement signé* d'un fichier signé en clair (fins de ligne `\n`).
/// Tout ce qui se trouve avant/après le bloc PGP n'est pas authentifié et est ignoré.
/// `None` si le contenu n'est pas un message signé en clair valide.
pub fn cleartext_body(content: &str) -> Option<String> {
    let (message, _) = CleartextSignedMessage::from_string(content).ok()?;
    Some(message.signed_text().replace("\r\n", "\n"))
}

pub fn detached_signature_path(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    SIGNATURE_EXTENSIONS
        .iter()
        .map(|ext| path.with_file_name(format!("{name}.{ext}")))
        .find(|candidate| candidate.is_file())
}

/// Cherche une signature parmi `sigs` valide pour `data` avec une clé du trousseau.
fn check_signatures(sigs: &[&Signature], data: &[u8], keys: &[SignedPublicKey]) -> SignatureStatus {
    for sig in sigs {
        for key in keys {
            if !with_any_key!(key, |k| sig.verify(k, data)) {
                continue;
            }
            let info = key_info(key);
            if info.revoked {
                return SignatureStatus::Invalid {
                    reason: InvalidReason::KeyRevoked { key_id: info.key_id },
                };
            }
            let signed_at = sig.created().map(|t| u64::from(t.as_secs()));
            return SignatureStatus::Valid {
                key_expired: signed_at.is_some_and(|t| expired_at(info.expires, t)),
                key: info,
                signed_at,
            };
        }
    }

    // Aucune clé ne valide : clé connue mais contenu différent, ou clé absente du trousseau ?
    if sigs.iter().any(|sig| keys.iter().any(|key| issued_by_cert(sig, key))) {
        return SignatureStatus::Invalid { reason: InvalidReason::ContentMismatch };
    }
    let issuer = sigs
        .iter()
        .find_map(|sig| {
            sig.issuer_fingerprint()
                .first()
                .map(|f| hex_upper(f.as_bytes()))
                .or_else(|| sig.issuer_key_id().first().map(|k| hex_upper(AsRef::<[u8]>::as_ref(*k))))
        })
        .unwrap_or_else(|| "inconnu".into());
    SignatureStatus::UnknownKey { issuer }
}

fn verify_clearsigned(content: &[u8], keys: &[SignedPublicKey]) -> SignatureStatus {
    let Ok(text) = std::str::from_utf8(content) else {
        return SignatureStatus::Invalid { reason: InvalidReason::NotUtf8 };
    };
    let Ok((message, _)) = CleartextSignedMessage::from_string(text.trim_start_matches('\u{feff}')) else {
        return SignatureStatus::Invalid { reason: InvalidReason::MalformedCleartext };
    };
    let signed_text = message.signed_text();
    let sigs: Vec<&Signature> = message.signatures().iter().collect();
    if sigs.is_empty() {
        return SignatureStatus::Absent;
    }
    check_signatures(&sigs, signed_text.as_bytes(), keys)
}

fn verify_detached(content: &[u8], signature: &[u8], keys: &[SignedPublicKey]) -> SignatureStatus {
    match DetachedSignature::from_reader_single(Cursor::new(signature.to_vec())) {
        Ok((detached, _)) => check_signatures(&[&detached.signature], content, keys),
        Err(e) => SignatureStatus::Invalid {
            reason: InvalidReason::SignatureUnreadable { detail: e.to_string() },
        },
    }
}

/// Vérifie l'authenticité du fichier de checksums `path` : signature en clair, sinon signature
/// détachée voisine (`.asc`, `.sig`, `.gpg`, `.sign`, `.pgp`).
pub fn verify_checksum_file(path: &Path, keys: &[SignedPublicKey]) -> SignatureStatus {
    let content = match read_limited(path) {
        Ok(c) => c,
        Err(reason) => return SignatureStatus::Invalid { reason },
    };
    if is_clearsigned(&content) {
        return verify_clearsigned(&content, keys);
    }
    let Some(sig_path) = detached_signature_path(path) else {
        return SignatureStatus::Absent;
    };
    match read_limited(&sig_path) {
        Ok(signature) => verify_detached(&content, &signature, keys),
        Err(reason) => SignatureStatus::Invalid { reason },
    }
}

fn read_limited(path: &Path) -> Result<Vec<u8>, InvalidReason> {
    let read_failed = |e: std::io::Error| InvalidReason::ReadFailed { detail: e.to_string() };
    let meta = fs::metadata(path).map_err(read_failed)?;
    if meta.len() > MAX_SIDECAR_BYTES {
        return Err(InvalidReason::TooLarge);
    }
    fs::read(path).map_err(read_failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMS: &[u8] = include_bytes!("../tests/fixtures/SHA256SUMS");
    const CLEARSIGNED: &[u8] = include_bytes!("../tests/fixtures/SHA256SUMS.clearsigned");
    const ED_SIG: &[u8] = include_bytes!("../tests/fixtures/SHA256SUMS.ed25519.asc");
    const RSA_SIG: &[u8] = include_bytes!("../tests/fixtures/SHA256SUMS.rsa3072.sig");
    const REVOKED_SIG: &[u8] = include_bytes!("../tests/fixtures/SHA256SUMS.revoked.asc");
    const ED_KEY: &[u8] = include_bytes!("../tests/fixtures/ed25519.pub.asc");
    const ED_KEY_BINARY: &[u8] = include_bytes!("../tests/fixtures/ed25519.pub.gpg");
    const RSA_KEY: &[u8] = include_bytes!("../tests/fixtures/rsa3072.pub.asc");
    const REVOKED_KEY: &[u8] = include_bytes!("../tests/fixtures/revoked.pub.asc");

    const ED_FPR: &str = "3FC40C125C34EB64C1F82B5D7116A443F0548603";

    fn scratch(tag: &str) -> PathBuf {
        // Les tests tournent en parallèle : un dossier distinct par appel.
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rustchk-pgp-{}-{tag}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn keys(blobs: &[&[u8]]) -> Vec<SignedPublicKey> {
        blobs.iter().flat_map(|b| parse_public_keys(b).unwrap()).collect()
    }

    fn verify_with(sums: &[u8], sig: Option<(&str, &[u8])>, keyring: &[SignedPublicKey]) -> SignatureStatus {
        let dir = scratch("verify");
        fs::write(dir.join("SHA256SUMS"), sums).unwrap();
        if let Some((ext, bytes)) = sig {
            fs::write(dir.join(format!("SHA256SUMS.{ext}")), bytes).unwrap();
        }
        let status = verify_checksum_file(&dir.join("SHA256SUMS"), keyring);
        fs::remove_dir_all(&dir).ok();
        status
    }

    #[test]
    fn reads_key_metadata() {
        let key = &keys(&[ED_KEY])[0];
        let info = key_info(key);
        assert_eq!(info.fingerprint, ED_FPR);
        assert_eq!(info.key_id, "7116A443F0548603");
        assert_eq!(info.user_ids, vec!["Test Release ed <release-ed@example.org>"]);
        assert_eq!(info.expires, None);
        assert!(!info.revoked);
        // La même clé au format binaire est identique.
        assert_eq!(key_info(&keys(&[ED_KEY_BINARY])[0]), info);
    }

    #[test]
    fn accepts_valid_armored_detached_signature() {
        match verify_with(SUMS, Some(("asc", ED_SIG)), &keys(&[ED_KEY])) {
            SignatureStatus::Valid { key, signed_at, key_expired } => {
                assert_eq!(key.fingerprint, ED_FPR);
                assert!(signed_at.is_some());
                assert!(!key_expired);
            }
            other => panic!("attendu Valid, obtenu {other:?}"),
        }
    }

    #[test]
    fn accepts_valid_binary_rsa_signature_under_every_extension() {
        for ext in ["sig", "gpg", "sign"] {
            let status = verify_with(SUMS, Some((ext, RSA_SIG)), &keys(&[RSA_KEY]));
            assert!(matches!(status, SignatureStatus::Valid { .. }), "{ext}: {status:?}");
        }
    }

    #[test]
    fn accepts_clearsigned_file() {
        let status = verify_with(CLEARSIGNED, None, &keys(&[ED_KEY]));
        assert!(matches!(status, SignatureStatus::Valid { .. }), "{status:?}");
    }

    #[test]
    fn rejects_modified_checksum_file() {
        let tampered = String::from_utf8(SUMS.to_vec()).unwrap().replacen("ba78", "ba79", 1);
        let status = verify_with(tampered.as_bytes(), Some(("asc", ED_SIG)), &keys(&[ED_KEY]));
        assert!(matches!(status, SignatureStatus::Invalid { .. }), "{status:?}");

        let tampered = String::from_utf8(CLEARSIGNED.to_vec()).unwrap().replacen("ba7816", "ba7817", 1);
        let status = verify_with(tampered.as_bytes(), None, &keys(&[ED_KEY]));
        assert!(matches!(status, SignatureStatus::Invalid { .. }), "{status:?}");
    }

    #[test]
    fn reports_unknown_signer_instead_of_trusting_it() {
        // Signature RSA, trousseau contenant seulement la clé ed25519.
        match verify_with(SUMS, Some(("sig", RSA_SIG)), &keys(&[ED_KEY])) {
            SignatureStatus::UnknownKey { issuer } => assert!(issuer.ends_with("BB76B2E5121F18F7"), "{issuer}"),
            other => panic!("attendu UnknownKey, obtenu {other:?}"),
        }
        // Trousseau vide.
        let status = verify_with(SUMS, Some(("asc", ED_SIG)), &[]);
        assert!(matches!(status, SignatureStatus::UnknownKey { .. }), "{status:?}");
    }

    #[test]
    fn rejects_signature_from_revoked_key() {
        let revoked = keys(&[REVOKED_KEY]);
        assert!(key_info(&revoked[0]).revoked);
        match verify_with(SUMS, Some(("asc", REVOKED_SIG)), &revoked) {
            SignatureStatus::Invalid { reason } => {
                assert_eq!(reason, InvalidReason::KeyRevoked { key_id: "7CB4341466211A96".into() })
            }
            other => panic!("attendu Invalid, obtenu {other:?}"),
        }
    }

    #[test]
    fn missing_or_garbage_signature() {
        assert_eq!(verify_with(SUMS, None, &keys(&[ED_KEY])), SignatureStatus::Absent);
        let status = verify_with(SUMS, Some(("asc", b"pas une signature")), &keys(&[ED_KEY]));
        assert!(matches!(status, SignatureStatus::Invalid { .. }), "{status:?}");
    }

    #[test]
    fn cleartext_body_refuses_unsigned_text_around_the_block() {
        let signed = String::from_utf8_lossy(CLEARSIGNED).into_owned();
        let body = cleartext_body(&signed).unwrap();
        assert!(body.contains("abc.bin"));
        assert!(!body.contains('\r'));

        let forged = format!("{}  evil.bin\n", "0".repeat(64));
        assert!(cleartext_body(&format!("{forged}{signed}")).is_none());
        assert!(cleartext_body(&format!("{signed}{forged}")).is_none());
        assert!(cleartext_body("simple texte").is_none());

        // Et la vérification de signature en clair refuse aussi ce contenu.
        let status = verify_with(format!("{forged}{signed}").as_bytes(), None, &keys(&[ED_KEY]));
        assert!(matches!(status, SignatureStatus::Invalid { .. }), "{status:?}");
    }

    #[test]
    fn rejects_non_key_input() {
        assert!(parse_public_keys(b"hello").is_err());
        assert!(parse_public_keys(SUMS).is_err());
        assert!(parse_public_keys(ED_SIG).is_err());
    }

    #[test]
    fn keyring_import_list_remove() {
        let dir = scratch("keyring");
        let ring = Keyring::new(dir.join("keys"));
        assert!(ring.list().is_empty());

        let imported = ring.import(ED_KEY).unwrap();
        ring.import(RSA_KEY).unwrap();
        assert_eq!(imported[0].fingerprint, ED_FPR);
        assert_eq!(ring.list().len(), 2);
        assert!(matches!(
            verify_checksum_file_from(&ring, ED_SIG),
            SignatureStatus::Valid { .. }
        ));

        assert!(ring.remove("../../etc").is_err());
        assert!(ring.remove("").is_err());
        ring.remove(&ED_FPR.to_ascii_lowercase()).unwrap();
        assert_eq!(ring.list().len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    fn verify_checksum_file_from(ring: &Keyring, sig: &[u8]) -> SignatureStatus {
        verify_with(SUMS, Some(("asc", sig)), &ring.load())
    }
}
