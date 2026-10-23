//! Chiffrement des clés d'API enregistrées sur disque.
//!
//! Windows : DPAPI (`CryptProtectData`), lié au compte de l'utilisateur ; un autre compte, ou une copie du
//! fichier sur une autre machine, ne peut pas les déchiffrer. Les autres systèmes n'ont pas d'équivalent
//! sans dépendance au trousseau du bureau : les clés y restent en clair.

/// Préfixe d'une valeur chiffrée (suivi des octets en hexadécimal). Une valeur sans préfixe est en clair :
/// ancien format, ou système autre que Windows.
const PREFIX: &str = "dpapi:";

/// Vrai si la valeur enregistrée est déjà chiffrée (ou vide), faux s'il faut la réenregistrer.
pub fn is_sealed(stored: &str) -> bool {
    stored.is_empty() || stored.starts_with(PREFIX) || !cfg!(windows)
}

/// Valeur à écrire sur disque pour `plain`.
pub fn seal(plain: &str) -> Result<String, String> {
    if plain.is_empty() || !cfg!(windows) {
        return Ok(plain.to_string());
    }
    Ok(format!("{PREFIX}{}", hex::encode(imp::protect(plain.as_bytes())?)))
}

/// Valeur en clair d'une valeur enregistrée ; `None` si elle ne peut pas être déchiffrée par ce compte.
pub fn open(stored: &str) -> Option<String> {
    match stored.strip_prefix(PREFIX) {
        None => Some(stored.to_string()),
        Some(encoded) => String::from_utf8(imp::unprotect(&hex::decode(encoded).ok()?).ok()?).ok(),
    }
}

#[cfg(windows)]
mod imp {
    use std::ptr;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// Entropie propre à l'application : une autre application du même compte doit la connaître pour
    /// déchiffrer les clés.
    const ENTROPY: &[u8] = b"app.rustchk/reputation-keys";

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr().cast_mut() }
    }

    /// Copie le résultat alloué par DPAPI puis le libère.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData.cast());
        bytes
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
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

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
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

#[cfg(not(windows))]
mod imp {
    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
    pub fn unprotect(_: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI is only available on Windows".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let sealed = seal("secret-key").unwrap();
        assert_eq!(open(&sealed).as_deref(), Some("secret-key"));
        assert!(is_sealed(&sealed));
        assert_eq!(seal("").unwrap(), "");
        if cfg!(windows) {
            assert!(sealed.starts_with(PREFIX));
            assert!(!sealed.contains("secret-key"));
        }
    }

    #[test]
    fn plain_and_corrupted_values() {
        // Ancien format en clair : lu tel quel, à réenregistrer sous Windows.
        assert_eq!(open("plain").as_deref(), Some("plain"));
        assert_eq!(is_sealed("plain"), !cfg!(windows));
        assert_eq!(open("dpapi:zz"), None);
        assert_eq!(open("dpapi:00112233"), None);
    }
}
