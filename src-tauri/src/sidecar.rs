//! Recherche d'un checksum publié à côté du fichier téléchargé
//! (`fichier.iso.sha256`, `SHA256SUMS`, …) pour pré-remplir la vérification.

use std::fs;
use std::path::Path;

use rustchk_core::{find_entry, Sidecar};

/// Extensions de fichiers de checksum propres à un fichier : `<fichier>.<ext>`.
const PER_FILE_EXTENSIONS: [&str; 9] =
    ["sha256", "sha512", "sha1", "md5", "sha384", "sha256sum", "sha512sum", "sha1sum", "md5sum"];

/// Noms (en minuscules) de fichiers de checksums couvrant tout un dossier.
const SUMS_FILES: [&str; 14] = [
    "sha256sums",
    "sha256sums.txt",
    "sha512sums",
    "sha512sums.txt",
    "sha1sums",
    "sha1sums.txt",
    "md5sums",
    "md5sums.txt",
    "sha256sum.txt",
    "checksums",
    "checksums.txt",
    "checksum.txt",
    "hashes.txt",
    "hashes.sha256",
];

/// Taille maximale lue d'un fichier de checksums (évite de charger un gros binaire par erreur).
pub(crate) const MAX_SIDECAR_BYTES: u64 = 1 << 20;

fn read_small(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SIDECAR_BYTES {
        return None;
    }
    // Les fichiers générés sous Windows peuvent être en UTF-8 ou ANSI : lecture tolérante.
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes).trim_start_matches('\u{feff}').to_string();
    if text.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
        // Fichier signé en clair : seul le texte à l'intérieur du bloc est authentifié.
        // Lire les lignes brutes laisserait un attaquant en ajouter avant ou après la signature.
        return crate::openpgp::cleartext_body(&text);
    }
    Some(text)
}

fn sidecar(path: &Path, hash: String) -> Option<Sidecar> {
    Some(Sidecar { source: path.file_name()?.to_string_lossy().into_owned(), path: path.display().to_string(), hash })
}

pub fn find(path: &Path) -> Option<Sidecar> {
    let dir = path.parent()?;
    let file_name = path.file_name()?.to_string_lossy().into_owned();

    for ext in PER_FILE_EXTENSIONS {
        let candidate = dir.join(format!("{file_name}.{ext}"));
        if let Some(entry) = read_small(&candidate).and_then(|c| find_entry(&c, &file_name, true)) {
            return sidecar(&candidate, entry.hash);
        }
    }

    for item in fs::read_dir(dir).ok()?.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        if !SUMS_FILES.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        if let Some(entry) = read_small(&item.path()).and_then(|c| find_entry(&c, &file_name, false)) {
            return sidecar(&item.path(), entry.hash);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rustchk-sidecar-{}-{tag}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_per_file_sidecar_even_if_renamed() {
        let dir = scratch_dir("perfile");
        fs::write(dir.join("tool (1).zip"), b"x").unwrap();
        fs::write(dir.join("tool (1).zip.sha256"), format!("{HASH}  tool.zip\n")).unwrap();
        let found = find(&dir.join("tool (1).zip")).unwrap();
        fs::remove_dir_all(&dir).ok();
        assert_eq!(found.hash, HASH);
        assert_eq!(found.source, "tool (1).zip.sha256");
    }

    #[test]
    fn finds_entry_in_sums_file_case_insensitively() {
        let dir = scratch_dir("sums");
        fs::write(dir.join("a.iso"), b"x").unwrap();
        fs::write(dir.join("SHA256SUMS"), format!("{}  b.iso\n{HASH} *a.iso\n", "0".repeat(64))).unwrap();
        let found = find(&dir.join("a.iso")).unwrap();
        fs::remove_dir_all(&dir).ok();
        assert_eq!(found.hash, HASH);
        assert_eq!(found.source, "SHA256SUMS");
    }

    #[test]
    fn only_trusts_text_inside_a_clearsigned_block() {
        let dir = scratch_dir("clearsigned");
        fs::write(dir.join("abc.bin"), b"x").unwrap();
        let signed = include_str!("../tests/fixtures/SHA256SUMS.clearsigned");

        fs::write(dir.join("SHA256SUMS"), signed).unwrap();
        let found = find(&dir.join("abc.bin")).unwrap();
        assert_eq!(found.hash, HASH);
        assert!(found.path.ends_with("SHA256SUMS"));

        // Une ligne forgée avant ou après le bloc signé : le fichier est rejeté en bloc,
        // jamais lu ligne à ligne.
        let forged = format!("{}  abc.bin\n", "0".repeat(64));
        fs::write(dir.join("SHA256SUMS"), format!("{forged}{signed}")).unwrap();
        assert!(find(&dir.join("abc.bin")).is_none());
        fs::write(dir.join("SHA256SUMS"), format!("{signed}{forged}")).unwrap();
        assert!(find(&dir.join("abc.bin")).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn returns_none_without_checksum_file() {
        let dir = scratch_dir("none");
        fs::write(dir.join("a.iso"), b"x").unwrap();
        let found = find(&dir.join("a.iso"));
        fs::remove_dir_all(&dir).ok();
        assert!(found.is_none());
    }
}
