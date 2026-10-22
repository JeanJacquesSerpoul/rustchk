//! Textes de l'interface en français et en anglais.
//!
//! Chaque message est une méthode de [`T`] dont le `match` couvre toutes les langues : en ajouter une
//! (`Lang::De`…) fait échouer la compilation tant qu'un texte manque.

use rustchk_core::{Algo, AppError, InvalidReason, KeyInfo, Lang};

#[derive(Clone, Copy)]
pub struct T(pub Lang);

impl T {
    fn pick<S>(self, fr: S, en: S) -> S {
        match self.0 {
            Lang::Fr => fr,
            Lang::En => en,
        }
    }

    // --- En-tête, fenêtre ---

    pub fn window_title(self) -> &'static str {
        self.pick("RustChk — Vérification de checksum", "RustChk — Checksum verification")
    }
    pub fn subtitle(self) -> &'static str {
        self.pick(
            "Vérifiez l'intégrité d'un fichier téléchargé",
            "Check the integrity of a downloaded file",
        )
    }
    pub fn language(self) -> &'static str {
        self.pick("Langue", "Language")
    }

    // --- Choix du fichier ---

    pub fn drop_title(self) -> &'static str {
        self.pick("Déposez un fichier ici", "Drop a file here")
    }
    pub fn or(self) -> &'static str {
        self.pick("ou", "or")
    }
    pub fn choose_file(self) -> &'static str {
        self.pick("Choisir un fichier…", "Choose a file…")
    }
    pub fn change(self) -> &'static str {
        self.pick("Changer…", "Change…")
    }
    pub fn size_and_time(self, size: u64, elapsed_ms: u64) -> String {
        let (size, time) = (format_size(self.0, size), format_duration(self.0, elapsed_ms));
        self.pick(format!("{size} · calculé en {time}"), format!("{size} · computed in {time}"))
    }
    pub fn hashing_progress(self, percent: f64) -> String {
        self.pick(
            format!("Calcul des empreintes… {percent:.0} %"),
            format!("Computing checksums… {percent:.0}%"),
        )
    }
    pub fn cancel(self) -> &'static str {
        self.pick("Annuler", "Cancel")
    }

    // --- Comparaison ---

    pub fn expected_label(self) -> &'static str {
        self.pick("Empreinte attendue", "Expected checksum")
    }
    pub fn expected_placeholder(self) -> &'static str {
        self.pick(
            "Collez ici le checksum publié par l'éditeur (MD5, SHA-1, SHA-256, SHA-384 ou SHA-512)",
            "Paste the checksum published by the vendor here (MD5, SHA-1, SHA-256, SHA-384 or SHA-512)",
        )
    }
    pub fn sidecar_read_before(self) -> &'static str {
        self.pick("Empreinte lue automatiquement dans ", "Checksum read automatically from ")
    }
    pub fn sidecar_read_after(self) -> &'static str {
        "."
    }
    pub fn verdict_pending(self) -> &'static str {
        self.pick("Calcul en cours…", "Computing…")
    }
    pub fn verdict_nothing(self) -> &'static str {
        self.pick(
            "Collez l'empreinte attendue pour la comparer.",
            "Paste the expected checksum to compare it.",
        )
    }
    pub fn verdict_invalid(self) -> &'static str {
        self.pick(
            "Format non reconnu : une empreinte compte 32, 40, 64, 96 ou 128 caractères hexadécimaux.",
            "Unrecognised format: a checksum is 32, 40, 64, 96 or 128 hexadecimal characters.",
        )
    }
    pub fn verdict_match(self, algo: Algo) -> String {
        let a = algo.label();
        self.pick(
            format!("✓ Fichier conforme — l'empreinte {a} correspond."),
            format!("✓ File matches — the {a} checksum is identical."),
        )
    }
    pub fn verdict_mismatch(self, algo: Algo) -> String {
        let a = algo.label();
        self.pick(
            format!("✗ Différent — l'empreinte {a} ne correspond pas. Le fichier est corrompu, incomplet ou n'est pas celui attendu."),
            format!("✗ Mismatch — the {a} checksum does not match. The file is corrupted, incomplete or not the expected one."),
        )
    }
    /// L'empreinte colle, mais le fichier de checksums est rejeté par sa signature.
    pub fn verdict_forged(self, algo: Algo) -> String {
        let a = algo.label();
        self.pick(
            format!("✗ L'empreinte {a} correspond, mais le fichier de checksums a été rejeté par sa signature OpenPGP (voir ci-dessous)."),
            format!("✗ The {a} checksum matches, but the checksum file was rejected by its OpenPGP signature (see below)."),
        )
    }
    pub fn computed_title(self) -> &'static str {
        self.pick("Empreintes calculées", "Computed checksums")
    }
    pub fn copy(self) -> &'static str {
        self.pick("Copier", "Copy")
    }

    // --- Signature OpenPGP ---

    pub fn sig_title(self, source: &str) -> String {
        self.pick(format!("Authenticité de {source}"), format!("Authenticity of {source}"))
    }
    pub fn sig_checking(self) -> &'static str {
        self.pick("Vérification de la signature OpenPGP…", "Checking the OpenPGP signature…")
    }
    pub fn sig_absent(self, source: &str) -> String {
        self.pick(
            format!("Aucune signature OpenPGP trouvée pour {source} : cette empreinte n'est pas authentifiée. Elle détecte une corruption, pas un fichier remplacé avec son checksum par un tiers."),
            format!("No OpenPGP signature found for {source}: this checksum is not authenticated. It detects corruption, not a file swapped together with its checksum by a third party."),
        )
    }
    fn on_date(self, date: &str) -> String {
        self.pick(format!(" le {date}"), format!(" on {date}"))
    }
    pub fn sig_valid(self, source: &str, signer: &str, key_id: &str, date: Option<&str>) -> String {
        let on = date.map(|d| self.on_date(d)).unwrap_or_default();
        self.pick(
            format!("✓ {source} est authentique — signé par {signer} (clé {key_id}){on}."),
            format!("✓ {source} is authentic — signed by {signer} (key {key_id}){on}."),
        )
    }
    pub fn sig_valid_expired(self, signer: &str, key_id: &str, date: Option<&str>) -> String {
        let on = date.map(|d| self.on_date(d)).unwrap_or_default();
        self.pick(
            format!("Signature valide, mais la clé avait expiré à la date de signature : {signer} (clé {key_id}){on}."),
            format!("Valid signature, but the key had already expired when it was made: {signer} (key {key_id}){on}."),
        )
    }
    pub fn key_fingerprint(self) -> &'static str {
        self.pick("Empreinte de la clé : ", "Key fingerprint: ")
    }
    pub fn key_compare_hint(self) -> &'static str {
        self.pick(
            "Comparez-la à celle publiée par l'éditeur sur un canal distinct du téléchargement.",
            "Compare it with the one published by the vendor over a channel separate from the download.",
        )
    }
    pub fn sig_unknown_before(self) -> &'static str {
        self.pick("Signature présente, mais faite par la clé ", "A signature is present, but it was made by key ")
    }
    pub fn sig_unknown_after(self) -> &'static str {
        self.pick(
            " qui n'est pas dans votre trousseau : elle n'est pas vérifiable.",
            " which is not in your keyring: it cannot be verified.",
        )
    }
    pub fn import_vendor_key(self) -> &'static str {
        self.pick("Importer la clé publique de l'éditeur…", "Import the vendor's public key…")
    }
    pub fn sig_rejected(self, reason: &InvalidReason) -> String {
        let reason = self.invalid_reason(reason);
        self.pick(
            format!("✗ Signature OpenPGP refusée : {reason} N'utilisez pas ce fichier."),
            format!("✗ OpenPGP signature rejected: {reason} Do not use this file."),
        )
    }
    pub fn invalid_reason(self, reason: &InvalidReason) -> String {
        match reason {
            InvalidReason::ContentMismatch => self.pick(
                "la signature ne correspond pas au contenu du fichier : il a été modifié ou est corrompu.".into(),
                "the signature does not match the file content: it was modified or is corrupted.".into(),
            ),
            InvalidReason::KeyRevoked { key_id } => self.pick(
                format!("la clé {key_id} a été révoquée."),
                format!("key {key_id} has been revoked."),
            ),
            InvalidReason::MalformedCleartext => self.pick(
                "le message signé en clair est illisible (tout texte hors du bloc signé est refusé).".into(),
                "the clear-signed message is malformed (any text outside the signed block is rejected).".into(),
            ),
            InvalidReason::NotUtf8 => self.pick(
                "le fichier signé n'est pas de l'UTF-8 valide.".into(),
                "the signed file is not valid UTF-8.".into(),
            ),
            InvalidReason::TooLarge => self.pick(
                "ce fichier est trop volumineux pour un fichier de checksums.".into(),
                "this file is too large to be a checksum file.".into(),
            ),
            InvalidReason::SignatureUnreadable { detail } => self.pick(
                format!("le fichier de signature est illisible ({detail})."),
                format!("the signature file cannot be read ({detail})."),
            ),
            InvalidReason::ReadFailed { detail } => self.pick(
                format!("lecture impossible : {detail}."),
                format!("could not read the file: {detail}."),
            ),
        }
    }

    // --- Trousseau ---

    pub fn keyring_title(self, count: usize) -> String {
        self.pick(
            format!("Trousseau OpenPGP ({count} clé{})", if count > 1 { "s" } else { "" }),
            format!("OpenPGP keyring ({count} key{})", if count == 1 { "" } else { "s" }),
        )
    }
    pub fn keyring_help(self) -> &'static str {
        self.pick(
            "Seules les clés importées ici sont utilisées pour authentifier les fichiers de checksums. Obtenez la clé publique de l'éditeur sur son site officiel et comparez son empreinte avant de l'importer.",
            "Only the keys imported here are used to authenticate checksum files. Get the vendor's public key from their official website and compare its fingerprint before importing it.",
        )
    }
    pub fn remove(self) -> &'static str {
        self.pick("Retirer", "Remove")
    }
    pub fn import_key(self) -> &'static str {
        self.pick("Importer une clé publique…", "Import a public key…")
    }
    pub fn key_revoked(self) -> &'static str {
        self.pick("révoquée", "revoked")
    }
    pub fn key_expires(self, date: &str) -> String {
        self.pick(format!("expire le {date}"), format!("expires on {date}"))
    }
    pub fn key_name(self, key: &KeyInfo) -> String {
        key.user_ids
            .first()
            .cloned()
            .unwrap_or_else(|| self.pick(format!("Clé {}", key.key_id), format!("Key {}", key.key_id)))
    }
    pub fn keys_imported(self, keys: &[KeyInfo]) -> String {
        let names = keys.iter().map(|k| self.key_name(k)).collect::<Vec<_>>().join(", ");
        self.pick(format!("Clé importée : {names}"), format!("Key imported: {names}"))
    }

    // --- Explorateur ---

    pub fn shell_label(self) -> &'static str {
        self.pick(
            "Ajouter « Vérifier le checksum » au menu contextuel de l'explorateur",
            "Add \"Verify checksum\" to the file explorer context menu",
        )
    }
    pub fn shell_added(self) -> &'static str {
        self.pick(
            "Ajouté au menu contextuel (clic droit › Afficher plus d'options sous Windows 11).",
            "Added to the context menu (right-click › Show more options on Windows 11).",
        )
    }
    pub fn shell_removed(self) -> &'static str {
        self.pick("Retiré du menu contextuel.", "Removed from the context menu.")
    }

    // --- Erreurs du backend ---

    pub fn error(self, error: &AppError) -> String {
        match error {
            AppError::Cancelled => self.pick("Opération annulée.".into(), "Operation cancelled.".into()),
            AppError::NotAFile => self.pick("ce n'est pas un fichier.".into(), "this is not a file.".into()),
            AppError::Io { detail } => self.pick(format!("Lecture impossible : {detail}"), format!("Could not read: {detail}")),
            AppError::KeyNotPublic { detail } => self.pick(
                format!("Ce fichier n'est pas une clé publique OpenPGP ({detail})."),
                format!("This file is not an OpenPGP public key ({detail})."),
            ),
            AppError::KeyUnreadable { detail } => {
                self.pick(format!("Clé illisible ({detail})."), format!("Unreadable key ({detail})."))
            }
            AppError::KeyBindingInvalid { detail } => self.pick(
                format!("Auto-signature de la clé invalide ({detail})."),
                format!("Invalid key self-signature ({detail})."),
            ),
            AppError::NoPublicKey => self.pick(
                "Aucune clé publique OpenPGP dans ce fichier.".into(),
                "No OpenPGP public key in this file.".into(),
            ),
            AppError::KeyFileTooLarge => self.pick(
                "Ce fichier est trop volumineux pour être une clé publique.".into(),
                "This file is too large to be a public key.".into(),
            ),
            AppError::KeyringWrite { detail } => self.pick(
                format!("Écriture dans le trousseau impossible : {detail}"),
                format!("Could not write to the keyring: {detail}"),
            ),
            AppError::KeyExport { detail } => self.pick(
                format!("Export de la clé impossible ({detail})."),
                format!("Could not export the key ({detail})."),
            ),
            AppError::InvalidFingerprint => self.pick("Empreinte invalide.".into(), "Invalid fingerprint.".into()),
            AppError::ShellUnsupported => self.pick(
                "L'intégration à l'explorateur n'est disponible que sous Windows.".into(),
                "File explorer integration is only available on Windows.".into(),
            ),
            AppError::Internal { detail } => self.pick(
                format!("Erreur interne : {detail}"),
                format!("Internal error: {detail}"),
            ),
        }
    }
}

/// Paramètres régionaux pour `Date.toLocaleDateString`.
pub fn date_locale(lang: Lang) -> &'static str {
    match lang {
        Lang::Fr => "fr-FR",
        Lang::En => "en-US",
    }
}

/// Octets lisibles : `1,50 Ko` en français, `1.50 KB` en anglais (unités binaires, base 1024).
pub fn format_size(lang: Lang, bytes: u64) -> String {
    let units: [&str; 5] = match lang {
        Lang::Fr => ["o", "Ko", "Mo", "Go", "To"],
        Lang::En => ["B", "KB", "MB", "GB", "TB"],
    };
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", units[0])
    } else {
        localize_decimal(lang, format!("{value:.2} {}", units[unit]))
    }
}

pub fn format_duration(lang: Lang, ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        localize_decimal(lang, format!("{:.1} s", ms as f64 / 1000.0))
    }
}

fn localize_decimal(lang: Lang, text: String) -> String {
    match lang {
        Lang::Fr => text.replace('.', ","),
        Lang::En => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_follow_the_language_conventions() {
        assert_eq!(format_size(Lang::Fr, 0), "0 o");
        assert_eq!(format_size(Lang::En, 1023), "1023 B");
        assert_eq!(format_size(Lang::Fr, 1536), "1,50 Ko");
        assert_eq!(format_size(Lang::En, 1536), "1.50 KB");
        assert_eq!(format_size(Lang::En, 5 * 1024 * 1024 * 1024), "5.00 GB");
        assert_eq!(format_duration(Lang::Fr, 3800), "3,8 s");
        assert_eq!(format_duration(Lang::En, 3800), "3.8 s");
        assert_eq!(format_duration(Lang::En, 12), "12 ms");
    }

    #[test]
    fn every_message_is_translated_differently() {
        let (fr, en) = (T(Lang::Fr), T(Lang::En));
        assert_ne!(fr.subtitle(), en.subtitle());
        assert_ne!(fr.verdict_match(Algo::Sha256), en.verdict_match(Algo::Sha256));
        assert!(en.verdict_match(Algo::Sha256).contains("SHA-256"));
        assert_eq!(en.keyring_title(1), "OpenPGP keyring (1 key)");
        assert_eq!(en.keyring_title(0), "OpenPGP keyring (0 keys)");
        assert_eq!(fr.keyring_title(0), "Trousseau OpenPGP (0 clé)");
        assert_eq!(fr.keyring_title(2), "Trousseau OpenPGP (2 clés)");
    }

    #[test]
    fn backend_errors_and_reasons_are_localized() {
        let io = AppError::Io { detail: "denied".into() };
        assert_eq!(T(Lang::Fr).error(&io), "Lecture impossible : denied");
        assert_eq!(T(Lang::En).error(&io), "Could not read: denied");
        let revoked = InvalidReason::KeyRevoked { key_id: "ABCD".into() };
        assert!(T(Lang::En).sig_rejected(&revoked).contains("key ABCD has been revoked"));
        assert!(T(Lang::Fr).sig_rejected(&revoked).contains("la clé ABCD a été révoquée"));
    }

    #[test]
    fn signature_headlines_mention_signer_and_optional_date() {
        let en = T(Lang::En);
        assert_eq!(
            en.sig_valid("SHA256SUMS", "Jane", "ABCD", Some("10/22/2026")),
            "✓ SHA256SUMS is authentic — signed by Jane (key ABCD) on 10/22/2026."
        );
        assert_eq!(
            T(Lang::Fr).sig_valid("SHA256SUMS", "Jane", "ABCD", None),
            "✓ SHA256SUMS est authentique — signé par Jane (clé ABCD)."
        );
    }
}
