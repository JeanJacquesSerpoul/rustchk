mod hashing;
mod openpgp;
mod shell;
mod sidecar;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustchk_core::{AppError, FileReport, KeyInfo, Lang, Progress, Sidecar, SignatureStatus};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

/// Chaque calcul reçoit un numéro ; incrémenter le compteur annule le précédent.
#[derive(Default)]
struct HashJobs(Arc<AtomicU64>);

/// Fichier passé en argument (menu contextuel, « Ouvrir avec », glisser sur l'exécutable).
#[tauri::command]
fn initial_file() -> Option<String> {
    std::env::args_os().skip(1).map(PathBuf::from).find(|p| p.is_file()).map(|p| p.display().to_string())
}

// Les seuls textes rédigés côté Rust sont ceux des fenêtres natives ; le reste est traduit par l'interface.
#[tauri::command]
async fn pick_file(app: AppHandle, lang: Lang) -> Option<String> {
    let title = match lang {
        Lang::Fr => "Choisir le fichier à vérifier",
        Lang::En => "Choose the file to verify",
    };
    app.dialog()
        .file()
        .set_title(title)
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

#[tauri::command]
async fn pick_key_file(app: AppHandle, lang: Lang) -> Option<String> {
    let (title, filter) = match lang {
        Lang::Fr => ("Choisir la clé publique OpenPGP du signataire", "Clés publiques OpenPGP"),
        Lang::En => ("Choose the signer's OpenPGP public key", "OpenPGP public keys"),
    };
    app.dialog()
        .file()
        .set_title(title)
        .add_filter(filter, &["asc", "gpg", "pgp", "key", "pub"])
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

#[tauri::command]
fn set_window_title(window: WebviewWindow, title: String) -> Result<(), AppError> {
    window.set_title(&title).map_err(|e| AppError::Internal { detail: e.to_string() })
}

fn io_error(e: std::io::Error) -> AppError {
    if e.kind() == std::io::ErrorKind::InvalidInput {
        AppError::NotAFile
    } else {
        AppError::Io { detail: e.to_string() }
    }
}

#[tauri::command]
async fn compute_hashes(
    window: WebviewWindow,
    jobs: State<'_, HashJobs>,
    path: String,
) -> Result<FileReport, AppError> {
    let counter = Arc::clone(&jobs.0);
    let job = counter.fetch_add(1, Ordering::SeqCst) + 1;

    tauri::async_runtime::spawn_blocking(move || {
        let result = hashing::hash_file(
            Path::new(&path),
            || counter.load(Ordering::SeqCst) != job,
            |done, total| {
                let _ = window.emit("hash-progress", Progress { done, total });
            },
        );
        match result {
            Ok(Some(report)) => Ok(report),
            Ok(None) => Err(AppError::Cancelled),
            Err(e) => Err(io_error(e)),
        }
    })
    .await
    .map_err(|e| AppError::Internal { detail: e.to_string() })?
}

#[tauri::command]
fn cancel_hash(jobs: State<'_, HashJobs>) {
    jobs.0.fetch_add(1, Ordering::SeqCst);
}

#[tauri::command]
fn find_sidecar(path: String) -> Option<Sidecar> {
    sidecar::find(Path::new(&path))
}

/// Trousseau OpenPGP de l'application (`%APPDATA%\<identifiant>\keys`).
fn keyring(app: &AppHandle) -> Result<openpgp::Keyring, AppError> {
    let dir = app.path().app_data_dir().map_err(|e| AppError::Internal { detail: e.to_string() })?;
    Ok(openpgp::Keyring::new(dir.join("keys")))
}

/// Authentifie un fichier de checksums (`path`) avec les clés du trousseau.
#[tauri::command]
async fn verify_signature(app: AppHandle, path: String) -> Result<SignatureStatus, AppError> {
    let ring = keyring(&app)?;
    tauri::async_runtime::spawn_blocking(move || openpgp::verify_checksum_file(Path::new(&path), &ring.load()))
        .await
        .map_err(|e| AppError::Internal { detail: e.to_string() })
}

#[tauri::command]
fn list_keys(app: AppHandle) -> Result<Vec<KeyInfo>, AppError> {
    Ok(keyring(&app)?.list())
}

#[tauri::command]
fn import_key(app: AppHandle, path: String) -> Result<Vec<KeyInfo>, AppError> {
    const MAX_KEY_FILE_BYTES: u64 = 4 << 20;
    let meta = std::fs::metadata(&path).map_err(io_error)?;
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(AppError::KeyFileTooLarge);
    }
    let data = std::fs::read(&path).map_err(io_error)?;
    keyring(&app)?.import(&data)
}

#[tauri::command]
fn remove_key(app: AppHandle, fingerprint: String) -> Result<(), AppError> {
    keyring(&app)?.remove(&fingerprint)
}

#[tauri::command]
fn shell_status() -> Result<bool, AppError> {
    shell::is_registered()
}

/// Ajoute (ou met à jour le libellé de) / retire l'entrée du menu contextuel.
#[tauri::command]
fn shell_set(enabled: bool, lang: Lang) -> Result<bool, AppError> {
    if enabled {
        shell::register(lang)?
    } else {
        shell::unregister()?
    }
    shell::is_registered()
}

/// Options `--register-shell [--lang fr|en]` / `--unregister-shell` : à lancer depuis un script ou
/// l'installeur, elles agissent sans ouvrir de fenêtre. Renvoie vrai si l'une d'elles a été traitée.
fn handle_cli_flags() -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let lang = args
        .iter()
        .position(|a| a == "--lang")
        .and_then(|i| args.get(i + 1))
        .and_then(|tag| Lang::from_tag(tag))
        .unwrap_or_else(shell::system_lang);
    let result = match args.first().map(String::as_str) {
        Some("--register-shell") => shell::register(lang),
        Some("--unregister-shell") => shell::unregister(),
        _ => return false,
    };
    if let Err(e) = result {
        eprintln!("rustchk : {e:?}");
        std::process::exit(1);
    }
    true
}

pub fn run() {
    if handle_cli_flags() {
        return;
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(HashJobs::default())
        .invoke_handler(tauri::generate_handler![
            initial_file,
            pick_file,
            pick_key_file,
            set_window_title,
            compute_hashes,
            cancel_hash,
            find_sidecar,
            verify_signature,
            list_keys,
            import_key,
            remove_key,
            shell_status,
            shell_set,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de RustChk");
}
