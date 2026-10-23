//! Signature Authenticode des exécutables et installeurs (`.exe`, `.msi`, `.dll`, `.ps1`…), vérifiée
//! par Windows (`WinVerifyTrust`) comme le fait l'explorateur, révocation des certificats comprise.
//!
//! Limite : seules les signatures intégrées au fichier sont lues ; un fichier système signé par
//! catalogue apparaît non signé. Les autres systèmes n'ont pas d'équivalent : `NotApplicable`.

use std::path::Path;

use rustchk_core::CodeSignature;

pub fn check(path: &Path) -> CodeSignature {
    imp::check(path)
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use rustchk_core::{CodeSignature, CodeSignatureProblem};
    use windows_sys::core::HRESULT;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::Cryptography::{
        CertGetNameStringW, CERT_CONTEXT, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    };
    use windows_sys::Win32::Security::WinTrust::*;

    pub fn check(path: &Path) -> CodeSignature {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY : `data` et `file` (et la chaîne `wide` qu'il pointe) vivent jusqu'à la fermeture de
        // l'état ; le signataire est lu avant cette fermeture, qui libère les données du fournisseur.
        let (status, last_error, signer) = unsafe {
            let status = WinVerifyTrust(ptr::null_mut(), &mut action, (&raw mut data).cast());
            let last_error = GetLastError() as HRESULT;
            let signer = signer_names(data.hWVTStateData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(ptr::null_mut(), &mut action, (&raw mut data).cast());
            (status, last_error, signer)
        };
        classify(status, last_error, signer)
    }

    fn classify(status: HRESULT, last_error: HRESULT, signer: Option<(String, Option<String>)>) -> CodeSignature {
        let rejected = |reason| CodeSignature::Rejected { signer: signer.clone().map(|(s, _)| s), reason };
        let valid = |revocation_checked| match signer.clone() {
            Some((signer, issuer)) => CodeSignature::Valid { signer, issuer, revocation_checked },
            None => rejected(CodeSignatureProblem::Malformed),
        };
        match status {
            0 => valid(true),
            CERT_E_REVOCATION_FAILURE => valid(false),
            // Sans fournisseur de signature pour ce type de fichier, WinVerifyTrust répond aussi « non
            // signé » : seul le dernier code d'erreur fait la différence.
            TRUST_E_NOSIGNATURE if matches!(last_error, TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN) => {
                CodeSignature::NotApplicable
            }
            TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => CodeSignature::NotApplicable,
            TRUST_E_NOSIGNATURE => CodeSignature::Unsigned,
            TRUST_E_BAD_DIGEST => rejected(CodeSignatureProblem::Tampered),
            CERT_E_REVOKED => rejected(CodeSignatureProblem::Revoked),
            CERT_E_EXPIRED => rejected(CodeSignatureProblem::Expired),
            CERT_E_UNTRUSTEDROOT | CERT_E_CHAINING | CERT_E_UNTRUSTEDTESTROOT => {
                rejected(CodeSignatureProblem::UntrustedRoot)
            }
            TRUST_E_EXPLICIT_DISTRUST => rejected(CodeSignatureProblem::Distrusted),
            TRUST_E_MALFORMED_SIGNATURE | TRUST_E_NO_SIGNER_CERT | TRUST_E_CERT_SIGNATURE => {
                rejected(CodeSignatureProblem::Malformed)
            }
            other => rejected(CodeSignatureProblem::Other { code: format!("0x{:08X}", other as u32) }),
        }
    }

    /// Nom du signataire et de l'autorité émettrice, lus dans le certificat feuille du premier signataire.
    unsafe fn signer_names(state: HANDLE) -> Option<(String, Option<String>)> {
        if state.is_null() {
            return None;
        }
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        if signer.is_null() {
            return None;
        }
        let cert = WTHelperGetProvCertFromChain(signer, 0);
        if cert.is_null() || (*cert).pCert.is_null() {
            return None;
        }
        let subject = cert_name((*cert).pCert, 0)?;
        Some((subject, cert_name((*cert).pCert, CERT_NAME_ISSUER_FLAG)))
    }

    unsafe fn cert_name(cert: *const CERT_CONTEXT, flags: u32) -> Option<String> {
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, ptr::null(), ptr::null_mut(), 0);
        if len <= 1 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, ptr::null(), buf.as_mut_ptr(), len);
        Some(String::from_utf16_lossy(&buf[..len as usize - 1]))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unsigned_executable_and_plain_file() {
            // Le binaire de test est un exécutable PE non signé.
            let exe = std::env::current_exe().unwrap();
            assert_eq!(check(&exe), CodeSignature::Unsigned);

            let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/SHA256SUMS");
            assert_eq!(check(&fixtures), CodeSignature::NotApplicable);
        }

        #[test]
        fn status_codes_map_to_problems() {
            let signer = Some(("Vendor".to_string(), Some("CA".to_string())));
            assert_eq!(
                classify(0, 0, signer.clone()),
                CodeSignature::Valid { signer: "Vendor".into(), issuer: Some("CA".into()), revocation_checked: true }
            );
            assert!(matches!(
                classify(CERT_E_REVOCATION_FAILURE, 0, signer.clone()),
                CodeSignature::Valid { revocation_checked: false, .. }
            ));
            assert_eq!(
                classify(TRUST_E_BAD_DIGEST, 0, signer),
                CodeSignature::Rejected { signer: Some("Vendor".into()), reason: CodeSignatureProblem::Tampered }
            );
            assert_eq!(classify(TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, None), CodeSignature::NotApplicable);
            assert_eq!(classify(TRUST_E_NOSIGNATURE, TRUST_E_NOSIGNATURE, None), CodeSignature::Unsigned);
            assert_eq!(
                classify(0x800B_0999_u32 as HRESULT, 0, None),
                CodeSignature::Rejected {
                    signer: None,
                    reason: CodeSignatureProblem::Other { code: "0x800B0999".into() }
                }
            );
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use rustchk_core::CodeSignature;

    pub fn check(_: &Path) -> CodeSignature {
        CodeSignature::NotApplicable
    }
}
