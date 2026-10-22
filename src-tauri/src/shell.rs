//! Intégration à l'explorateur de fichiers : entrée « Vérifier le checksum » dans le
//! menu contextuel de tous les fichiers.
//!
//! Windows : verbe classique sous `HKCU\Software\Classes\*\shell` (sans droits administrateur).
//! Sous Windows 11 il apparaît dans « Afficher plus d'options » (Maj+F10).
//! L'installeur NSIS (`windows/hooks.nsh`) écrit la même clé.

use rustchk_core::{AppError, Lang};

/// Libellé du verbe dans le menu contextuel.
pub fn menu_label(lang: Lang) -> &'static str {
    match lang {
        Lang::Fr => "Vérifier le checksum (RustChk)",
        Lang::En => "Verify checksum (RustChk)",
    }
}

#[cfg(windows)]
mod imp {
    use std::io;

    use rustchk_core::Lang;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    const VERB_KEY: &str = r"Software\Classes\*\shell\RustChk";
    const COMMAND_KEY: &str = r"Software\Classes\*\shell\RustChk\command";

    fn exe_path() -> io::Result<String> {
        let exe = std::env::current_exe()?;
        // `current_exe` peut renvoyer un chemin étendu `\\?\C:\...` que l'explorateur n'aime pas.
        Ok(exe.display().to_string().trim_start_matches(r"\\?\").to_string())
    }

    fn command_line(exe: &str) -> String {
        format!("\"{exe}\" \"%1\"")
    }

    /// Vrai si l'entrée existe *et* pointe vers l'exécutable en cours (sinon elle est périmée).
    pub fn is_registered() -> io::Result<bool> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok(key) = hkcu.open_subkey(COMMAND_KEY) else {
            return Ok(false);
        };
        let current: String = key.get_value("").unwrap_or_default();
        Ok(current.eq_ignore_ascii_case(&command_line(&exe_path()?)))
    }

    pub fn register(lang: Lang) -> io::Result<()> {
        let exe = exe_path()?;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (verb, _) = hkcu.create_subkey(VERB_KEY)?;
        verb.set_value("", &super::menu_label(lang))?;
        verb.set_value("Icon", &format!("\"{exe}\",0"))?;
        let (command, _) = hkcu.create_subkey(COMMAND_KEY)?;
        command.set_value("", &command_line(&exe))?;
        Ok(())
    }

    pub fn unregister() -> io::Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        match hkcu.delete_subkey_all(VERB_KEY) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Langue du système (paramètres régionaux de l'utilisateur), ex. `fr-FR`.
    pub fn system_locale() -> Option<String> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Control Panel\International")
            .ok()?
            .get_value("LocaleName")
            .ok()
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;

    use rustchk_core::Lang;

    pub fn is_registered() -> io::Result<bool> {
        Ok(false)
    }
    pub fn register(_: Lang) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    pub fn unregister() -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    pub fn system_locale() -> Option<String> {
        std::env::var("LANG").ok()
    }
}

fn to_app_error(e: std::io::Error) -> AppError {
    if e.kind() == std::io::ErrorKind::Unsupported {
        AppError::ShellUnsupported
    } else {
        AppError::Io { detail: e.to_string() }
    }
}

pub fn is_registered() -> Result<bool, AppError> {
    imp::is_registered().map_err(to_app_error)
}

pub fn register(lang: Lang) -> Result<(), AppError> {
    imp::register(lang).map_err(to_app_error)
}

pub fn unregister() -> Result<(), AppError> {
    imp::unregister().map_err(to_app_error)
}

/// Langue par défaut quand l'interface n'est pas là pour la choisir (options en ligne de commande).
pub fn system_lang() -> Lang {
    imp::system_locale().map_or(Lang::En, |tag| Lang::detect(&tag))
}
