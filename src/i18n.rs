//! Textes de l'interface en français et en anglais.
//!
//! Chaque message est une méthode de [`T`] dont le `match` couvre toutes les langues : en ajouter une
//! (`Lang::De`…) fait échouer la compilation tant qu'un texte manque.

use rustchk_core::{
    Algo, AppError, CodeSignatureProblem, InvalidReason, KeyInfo, Lang, Lookup, LookupError, Service, Threat,
};

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
        self.pick("Vérifiez l'intégrité d'un fichier téléchargé", "Check the integrity of a downloaded file")
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
        self.pick(format!("Calcul des empreintes… {percent:.0} %"), format!("Computing checksums… {percent:.0}%"))
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
        self.pick("Collez l'empreinte attendue pour la comparer.", "Paste the expected checksum to compare it.")
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
            InvalidReason::KeyRevoked { key_id } => {
                self.pick(format!("la clé {key_id} a été révoquée."), format!("key {key_id} has been revoked."))
            }
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
            InvalidReason::ReadFailed { detail } => {
                self.pick(format!("lecture impossible : {detail}."), format!("could not read the file: {detail}."))
            }
        }
    }

    // --- Signature Authenticode ---

    pub fn code_title(self) -> &'static str {
        self.pick("Signature de l'éditeur (Authenticode)", "Publisher signature (Authenticode)")
    }
    pub fn code_unsigned(self) -> &'static str {
        self.pick(
            "Ce programme n'est pas signé : rien n'atteste qui l'a publié. Méfiez-vous d'un installeur non signé venant d'un éditeur connu.",
            "This program is not signed: nothing proves who published it. Be wary of an unsigned installer from a well-known vendor.",
        )
    }
    pub fn code_valid(self, signer: &str) -> String {
        self.pick(
            format!("✓ Signé par {signer} — signature valide, reconnue par Windows."),
            format!("✓ Signed by {signer} — valid signature, trusted by Windows."),
        )
    }
    pub fn code_issuer(self, issuer: &str) -> String {
        self.pick(format!("Certificat délivré par {issuer}."), format!("Certificate issued by {issuer}."))
    }
    pub fn code_revocation_unchecked(self) -> &'static str {
        self.pick(
            "La révocation du certificat n'a pas pu être vérifiée (pas d'accès réseau ?).",
            "The certificate's revocation status could not be checked (no network access?).",
        )
    }
    pub fn code_compare_hint(self) -> &'static str {
        self.pick(
            "Vérifiez que ce nom est bien celui de l'éditeur attendu : une signature valide prouve l'origine, pas l'innocuité.",
            "Check that this is the publisher you expect: a valid signature proves the origin, not that the file is harmless.",
        )
    }
    pub fn code_rejected(self, signer: Option<&str>, problem: &CodeSignatureProblem) -> String {
        let reason = self.code_problem(problem);
        match signer {
            Some(signer) => self.pick(
                format!("✗ Signature au nom de {signer} refusée : {reason} N'exécutez pas ce fichier."),
                format!("✗ Signature in the name of {signer} rejected: {reason} Do not run this file."),
            ),
            None => self.pick(
                format!("✗ Signature refusée : {reason} N'exécutez pas ce fichier."),
                format!("✗ Signature rejected: {reason} Do not run this file."),
            ),
        }
    }
    fn code_problem(self, problem: &CodeSignatureProblem) -> String {
        match problem {
            CodeSignatureProblem::Tampered => self.pick(
                "le fichier a été modifié après avoir été signé.".into(),
                "the file was modified after it was signed.".into(),
            ),
            CodeSignatureProblem::Revoked => self.pick(
                "le certificat a été révoqué par son autorité (souvent après un vol).".into(),
                "the certificate was revoked by its authority (often after being stolen).".into(),
            ),
            CodeSignatureProblem::Expired => self.pick(
                "le certificat a expiré et la signature n'est pas horodatée.".into(),
                "the certificate has expired and the signature is not timestamped.".into(),
            ),
            CodeSignatureProblem::UntrustedRoot => self.pick(
                "le certificat ne provient pas d'une autorité reconnue par Windows (auto-signé ?).".into(),
                "the certificate does not come from an authority trusted by Windows (self-signed?).".into(),
            ),
            CodeSignatureProblem::Distrusted => self.pick(
                "le certificat est explicitement marqué comme non fiable.".into(),
                "the certificate is explicitly marked as untrusted.".into(),
            ),
            CodeSignatureProblem::Malformed => {
                self.pick("la signature est malformée.".into(), "the signature is malformed.".into())
            }
            CodeSignatureProblem::Other { code } => {
                self.pick(format!("erreur Windows {code}."), format!("Windows error {code}."))
            }
        }
    }

    // --- Analyse en ligne ---

    pub fn reputation_title(self) -> &'static str {
        self.pick("Analyse antimalware en ligne", "Online malware check")
    }
    pub fn reputation_checking(self) -> &'static str {
        self.pick("Recherche de l'empreinte SHA-256…", "Looking up the SHA-256 checksum…")
    }
    pub fn reputation_privacy(self) -> &'static str {
        self.pick(
            "Seule l'empreinte SHA-256 a été envoyée, jamais le fichier. Un fichier inconnu n'est pas pour autant sain.",
            "Only the SHA-256 checksum was sent, never the file. An unknown file is not necessarily safe.",
        )
    }
    pub fn lookup(self, service: Service, lookup: &Lookup) -> String {
        let s = service.label();
        match lookup {
            Lookup::Unknown => self.pick(
                format!("{s} : empreinte inconnue, aucun signalement."),
                format!("{s}: unknown checksum, never reported."),
            ),
            Lookup::Listed { family, tags } => {
                let family = family.as_deref().map(|f| format!(" ({f})")).unwrap_or_default();
                let tags = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
                self.pick(
                    format!("✗ {s} : malware répertorié{family}{tags}. N'ouvrez pas ce fichier."),
                    format!("✗ {s}: known malware{family}{tags}. Do not open this file."),
                )
            }
            Lookup::Scanned { malicious, suspicious, engines, label } => {
                let label = label.as_deref().map(|l| format!(" ({l})")).unwrap_or_default();
                match lookup.threat() {
                    Threat::Malicious => self.pick(
                        format!("✗ {s} : détecté par {malicious} antivirus sur {engines}{label}. N'ouvrez pas ce fichier."),
                        format!("✗ {s}: flagged by {malicious} of {engines} antivirus engines{label}. Do not open this file."),
                    ),
                    Threat::Suspicious => self.pick(
                        format!("{s} : {malicious} détection(s) et {suspicious} alerte(s) sur {engines} antivirus{label} — peut-être un faux positif, restez prudent."),
                        format!("{s}: {malicious} detection(s) and {suspicious} warning(s) from {engines} engines{label} — possibly a false positive, be careful."),
                    ),
                    _ => self.pick(
                        format!("✓ {s} : aucun des {engines} antivirus ne détecte ce fichier."),
                        format!("✓ {s}: none of the {engines} antivirus engines flag this file."),
                    ),
                }
            }
            Lookup::Failed { error } => {
                let reason = match error {
                    LookupError::InvalidKey => self.pick("clé d'API refusée.".into(), "API key rejected.".into()),
                    LookupError::RateLimited => self.pick(
                        "quota de requêtes dépassé, réessayez plus tard.".into(),
                        "request quota exceeded, try again later.".into(),
                    ),
                    LookupError::Network { detail } => self
                        .pick(format!("service injoignable ({detail})."), format!("service unreachable ({detail}).")),
                    LookupError::Unexpected { detail } => {
                        self.pick(format!("réponse inattendue ({detail})."), format!("unexpected response ({detail})."))
                    }
                };
                self.pick(format!("{s} : vérification impossible — {reason}"), format!("{s}: check failed — {reason}"))
            }
        }
    }
    pub fn reputation_settings_title(self) -> &'static str {
        self.pick("Analyse en ligne (MalwareBazaar, VirusTotal)", "Online check (MalwareBazaar, VirusTotal)")
    }
    pub fn reputation_help(self) -> &'static str {
        self.pick(
            "Désactivée par défaut. Une fois activée, l'empreinte SHA-256 de chaque fichier vérifié — et rien d'autre — est envoyée aux services dont la clé est renseignée. Clés gratuites : auth.abuse.ch (MalwareBazaar) et virustotal.com (compte, puis « API key »).",
            "Off by default. Once enabled, the SHA-256 checksum of every file you verify — and nothing else — is sent to the services whose key is filled in. Free keys: auth.abuse.ch (MalwareBazaar) and virustotal.com (account, then \"API key\").",
        )
    }
    pub fn reputation_enable(self) -> &'static str {
        self.pick(
            "Rechercher l'empreinte des fichiers vérifiés sur ces services",
            "Look up the checksum of verified files on these services",
        )
    }
    pub fn api_key_label(self, service: Service) -> String {
        let s = service.label();
        self.pick(format!("Clé d'API {s}"), format!("{s} API key"))
    }
    pub fn api_key_placeholder(self, service: Service) -> &'static str {
        match service {
            Service::MalwareBazaar => self.pick("Auth-Key abuse.ch", "abuse.ch Auth-Key"),
            Service::VirusTotal => self.pick("Clé personnelle VirusTotal", "Personal VirusTotal key"),
        }
    }
    pub fn reputation_keys_storage(self) -> &'static str {
        self.pick(
            "Les clés sont enregistrées chiffrées pour votre compte Windows (DPAPI), dans reputation.json à côté du trousseau.",
            "Keys are stored encrypted for your Windows account (DPAPI), in reputation.json next to the keyring.",
        )
    }
    pub fn save(self) -> &'static str {
        self.pick("Enregistrer", "Save")
    }
    pub fn settings_saved(self) -> &'static str {
        self.pick("Réglages enregistrés.", "Settings saved.")
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
            AppError::Io { detail } => {
                self.pick(format!("Lecture impossible : {detail}"), format!("Could not read: {detail}"))
            }
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
            AppError::InvalidHash => {
                self.pick("Empreinte SHA-256 invalide.".into(), "Invalid SHA-256 checksum.".into())
            }
            AppError::SettingsWrite { detail } => self.pick(
                format!("Enregistrement des réglages impossible : {detail}"),
                format!("Could not save the settings: {detail}"),
            ),
            AppError::ShellUnsupported => self.pick(
                "L'intégration à l'explorateur n'est disponible que sous Windows.".into(),
                "File explorer integration is only available on Windows.".into(),
            ),
            AppError::Internal { detail } => {
                self.pick(format!("Erreur interne : {detail}"), format!("Internal error: {detail}"))
            }
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
    fn lookup_messages_follow_the_threat_level() {
        let en = T(Lang::En);
        let scanned = |malicious| Lookup::Scanned { malicious, suspicious: 0, engines: 70, label: None };
        assert_eq!(
            en.lookup(Service::VirusTotal, &scanned(0)),
            "✓ VirusTotal: none of the 70 antivirus engines flag this file."
        );
        assert!(en.lookup(Service::VirusTotal, &scanned(1)).contains("possibly a false positive"));
        assert!(en.lookup(Service::VirusTotal, &scanned(40)).starts_with("✗ VirusTotal: flagged by 40 of 70"));
        let listed = Lookup::Listed { family: Some("RedLineStealer".into()), tags: vec!["exe".into()] };
        assert_eq!(
            T(Lang::Fr).lookup(Service::MalwareBazaar, &listed),
            "✗ MalwareBazaar : malware répertorié (RedLineStealer) [exe]. N'ouvrez pas ce fichier."
        );
        let failed = Lookup::Failed { error: LookupError::InvalidKey };
        assert_eq!(en.lookup(Service::MalwareBazaar, &failed), "MalwareBazaar: check failed — API key rejected.");
    }

    #[test]
    fn code_signature_messages() {
        let en = T(Lang::En);
        assert_eq!(
            en.code_valid("Mozilla Corporation"),
            "✓ Signed by Mozilla Corporation — valid signature, trusted by Windows."
        );
        assert!(en.code_rejected(Some("ACME"), &CodeSignatureProblem::Tampered).contains("ACME"));
        assert!(T(Lang::Fr).code_rejected(None, &CodeSignatureProblem::Revoked).contains("révoqué"));
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
