//! Protection des clés d'API enregistrées.
//!
//! - Windows : DPAPI (`CryptProtectData`), lié au compte de l'utilisateur ; un autre compte, ou une copie du
//!   fichier sur une autre machine, ne peut pas les déchiffrer. La valeur chiffrée reste dans le fichier.
//! - Linux : trousseau du bureau via Secret Service (GNOME Keyring, KWallet…), chiffré et déverrouillé à la
//!   connexion. Sans trousseau joignable (session sans D-Bus, gestionnaire de fenêtres minimal), les clés
//!   restent en clair.
//! - macOS : trousseau de session (Keychain).
//!
//! Dans un trousseau, le fichier ne garde qu'un marqueur et chaque clé est désignée par un couple
//! (`service`, `user`).

use rustchk_core::KeyStorage;

/// Préfixe d'une valeur chiffrée par DPAPI (suivi des octets en hexadécimal).
const DPAPI_PREFIX: &str = "dpapi:";
/// Valeur enregistrée à la place d'une clé rangée dans le trousseau du système.
const KEYRING_MARKER: &str = "keyring:";

/// Protection appliquée aux clés enregistrées à partir de maintenant.
pub fn storage() -> KeyStorage {
    imp::storage()
}

/// Vrai si la valeur enregistrée est protégée (ou vide) ; une valeur en clair est l'ancien format, ou le
/// repli d'un système sans trousseau.
pub fn is_sealed(stored: &str) -> bool {
    stored.is_empty() || stored.starts_with(DPAPI_PREFIX) || stored == KEYRING_MARKER
}

/// Protège `plain` et renvoie la valeur à écrire dans le fichier. Une clé vide est retirée du trousseau.
pub fn seal(service: &str, user: &str, plain: &str) -> Result<String, String> {
    imp::seal(service, user, plain)
}

/// Clé en clair d'une valeur enregistrée ; `None` si ce compte ne peut pas la retrouver (autre compte,
/// autre machine, trousseau verrouillé ou absent).
pub fn open(service: &str, user: &str, stored: &str) -> Option<String> {
    if !is_sealed(stored) {
        return Some(stored.to_string());
    }
    imp::open(service, user, stored)
}

#[cfg(windows)]
mod imp {
    use std::ptr;

    use rustchk_core::KeyStorage;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use super::DPAPI_PREFIX;

    /// Entropie propre à l'application : une autre application du même compte doit la connaître pour
    /// déchiffrer les clés.
    const ENTROPY: &[u8] = b"app.rustchk/reputation-keys";

    pub fn storage() -> KeyStorage {
        KeyStorage::Dpapi
    }

    pub fn seal(_: &str, _: &str, plain: &str) -> Result<String, String> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        Ok(format!("{DPAPI_PREFIX}{}", hex::encode(protect(plain.as_bytes())?)))
    }

    pub fn open(_: &str, _: &str, stored: &str) -> Option<String> {
        if stored.is_empty() {
            return Some(String::new());
        }
        let encrypted = hex::decode(stored.strip_prefix(DPAPI_PREFIX)?).ok()?;
        String::from_utf8(unprotect(&encrypted).ok()?).ok()
    }

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr().cast_mut() }
    }

    /// Copie le résultat alloué par DPAPI puis le libère.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData.cast());
        bytes
    }

    fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        let (input, entropy) = (blob(data), blob(ENTROPY));
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY : les blobs d'entrée pointent vers des tranches vivantes pendant l'appel, qui ne les
        // modifie pas ; `out` est alloué par DPAPI et libéré par `take`.
        unsafe {
            if CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(take(out))
        }
    }

    fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        let (input, entropy) = (blob(data), blob(ENTROPY));
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY : comme `protect`.
        unsafe {
            if CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(take(out))
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::sync::{Arc, OnceLock};

    use keyring_core::{CredentialStore, Entry, Error};
    use rustchk_core::KeyStorage;

    use super::KEYRING_MARKER;

    #[cfg(target_os = "linux")]
    const STORAGE: KeyStorage = KeyStorage::SecretService;
    #[cfg(target_os = "macos")]
    const STORAGE: KeyStorage = KeyStorage::Keychain;

    #[cfg(target_os = "linux")]
    fn connect() -> Option<Arc<CredentialStore>> {
        // Échoue sans bus de session ou sans service Secret Service.
        let store: Arc<CredentialStore> = dbus_secret_service_keyring_store::Store::new().ok()?;
        Some(store)
    }

    #[cfg(target_os = "macos")]
    fn connect() -> Option<Arc<CredentialStore>> {
        let store: Arc<CredentialStore> = apple_native_keyring_store::keychain::Store::new().ok()?;
        Some(store)
    }

    /// Trousseau ouvert une fois pour toutes ; `None` s'il est injoignable.
    fn store() -> Option<&'static Arc<CredentialStore>> {
        static STORE: OnceLock<Option<Arc<CredentialStore>>> = OnceLock::new();
        STORE.get_or_init(connect).as_ref()
    }

    fn entry(store: &CredentialStore, service: &str, user: &str) -> Result<Entry, Error> {
        // Libellé affiché par Seahorse ou KWallet ; le trousseau macOS affiche le nom du service.
        #[cfg(target_os = "linux")]
        let label = format!("RustChk — {user} API key");
        #[cfg(target_os = "linux")]
        let modifiers = Some(std::collections::HashMap::from([("label", label.as_str())]));
        #[cfg(target_os = "macos")]
        let modifiers = None::<std::collections::HashMap<&str, &str>>;
        store.build(service, user, modifiers.as_ref())
    }

    pub fn storage() -> KeyStorage {
        if store().is_some() {
            STORAGE
        } else {
            KeyStorage::Plain
        }
    }

    pub fn seal(service: &str, user: &str, plain: &str) -> Result<String, String> {
        let Some(store) = store() else {
            return Ok(plain.to_string());
        };
        let entry = entry(store.as_ref(), service, user).map_err(|e| e.to_string())?;
        if plain.is_empty() {
            return match entry.delete_credential() {
                Ok(()) | Err(Error::NoEntry) => Ok(String::new()),
                Err(e) => Err(e.to_string()),
            };
        }
        // Trousseau verrouillé et déverrouillage refusé, notamment : ne pas se replier sur du texte en clair.
        entry.set_password(plain).map_err(|e| e.to_string())?;
        Ok(KEYRING_MARKER.to_string())
    }

    pub fn open(service: &str, user: &str, stored: &str) -> Option<String> {
        match stored {
            "" => Some(String::new()),
            KEYRING_MARKER => entry(store()?.as_ref(), service, user).ok()?.get_password().ok(),
            // Valeur DPAPI d'un fichier copié depuis Windows.
            _ => None,
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod imp {
    use rustchk_core::KeyStorage;

    pub fn storage() -> KeyStorage {
        KeyStorage::Plain
    }

    pub fn seal(_: &str, _: &str, plain: &str) -> Result<String, String> {
        Ok(plain.to_string())
    }

    pub fn open(_: &str, _: &str, stored: &str) -> Option<String> {
        stored.is_empty().then(String::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Service propre aux tests, pour ne jamais toucher aux clés réelles du poste.
    const SERVICE: &str = "app.rustchk.test-secret";

    #[test]
    fn round_trip_follows_the_storage() {
        // La CI lance un vrai trousseau sur chaque système : échouer plutôt que de tester en silence le repli
        // en clair.
        if let Ok(expected) = std::env::var("RUSTCHK_EXPECT_KEY_STORAGE") {
            assert_eq!(format!("{:?}", storage()), expected);
        }
        let sealed = seal(SERVICE, "round-trip", "secret-key").unwrap();
        assert_eq!(open(SERVICE, "round-trip", &sealed).as_deref(), Some("secret-key"));
        match storage() {
            KeyStorage::Dpapi => assert!(sealed.starts_with(DPAPI_PREFIX) && !sealed.contains("secret-key")),
            KeyStorage::SecretService | KeyStorage::Keychain => assert_eq!(sealed, KEYRING_MARKER),
            KeyStorage::Plain => assert_eq!(sealed, "secret-key"),
        }
        assert_eq!(is_sealed(&sealed), storage() != KeyStorage::Plain);

        // Clé effacée : retirée du trousseau.
        assert_eq!(seal(SERVICE, "round-trip", "").unwrap(), "");
        if matches!(storage(), KeyStorage::SecretService | KeyStorage::Keychain) {
            assert_eq!(open(SERVICE, "round-trip", KEYRING_MARKER), None);
        }
    }

    #[test]
    fn plain_and_foreign_values() {
        // Ancien format en clair : lu tel quel.
        assert_eq!(open(SERVICE, "plain", "plain").as_deref(), Some("plain"));
        assert!(!is_sealed("plain"));
        assert_eq!(open(SERVICE, "plain", ""), Some(String::new()));
        // Valeur DPAPI corrompue ou venue d'un autre compte, marqueur sans entrée dans le trousseau.
        assert_eq!(open(SERVICE, "foreign", "dpapi:zz"), None);
        assert_eq!(open(SERVICE, "foreign", "dpapi:00112233"), None);
        assert_eq!(open(SERVICE, "missing", KEYRING_MARKER), None);
    }
}
