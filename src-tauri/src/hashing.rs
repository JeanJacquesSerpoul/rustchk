//! Calcul MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 en une seule lecture du fichier.
//! Un thread lit le fichier par blocs, un thread par algorithme les consomme en parallèle.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use md5::Md5;
use rustchk_core::{FileReport, Hashes};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

const CHUNK: usize = 1 << 20;
const QUEUE_DEPTH: usize = 4;
const PROGRESS_EVERY: Duration = Duration::from_millis(60);

type Chunk = Arc<[u8]>;

fn digest_worker<D: Digest>(rx: Receiver<Chunk>) -> String {
    let mut hasher = D::new();
    for chunk in rx {
        hasher.update(&chunk[..]);
    }
    hex::encode(hasher.finalize())
}

/// Hache `path`. Renvoie `Ok(None)` si `cancelled()` est devenu vrai en cours de route.
pub fn hash_file(
    path: &Path,
    cancelled: impl Fn() -> bool,
    mut on_progress: impl FnMut(u64, u64),
) -> io::Result<Option<FileReport>> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        // Le type d'erreur est converti en `AppError::NotAFile` par l'appelant.
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    let total = meta.len();
    let started = Instant::now();

    let workers: [fn(Receiver<Chunk>) -> String; 5] = [
        digest_worker::<Md5>,
        digest_worker::<Sha1>,
        digest_worker::<Sha256>,
        digest_worker::<Sha384>,
        digest_worker::<Sha512>,
    ];

    let outcome = thread::scope(|scope| -> io::Result<Option<[String; 5]>> {
        let mut senders: Vec<SyncSender<Chunk>> = Vec::with_capacity(workers.len());
        let mut handles = Vec::with_capacity(workers.len());
        for worker in workers {
            let (tx, rx) = sync_channel::<Chunk>(QUEUE_DEPTH);
            senders.push(tx);
            handles.push(scope.spawn(move || worker(rx)));
        }

        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        let mut last_report = Instant::now();
        let mut was_cancelled = false;
        let mut read_error = None;

        loop {
            if cancelled() {
                was_cancelled = true;
                break;
            }
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    read_error = Some(e);
                    break;
                }
            };
            let chunk: Chunk = Arc::from(&buf[..n]);
            for tx in &senders {
                // Un worker qui a paniqué ferme son canal : on ignore, le join le signalera.
                let _ = tx.send(Arc::clone(&chunk));
            }
            done += n as u64;
            if last_report.elapsed() >= PROGRESS_EVERY {
                on_progress(done, total);
                last_report = Instant::now();
            }
        }

        drop(senders);
        let mut digests = Vec::with_capacity(handles.len());
        for handle in handles {
            let digest = handle.join().map_err(|_| io::Error::other("hash worker thread panicked"))?;
            digests.push(digest);
        }
        if let Some(e) = read_error {
            return Err(e);
        }
        if was_cancelled {
            return Ok(None);
        }
        on_progress(total, total);
        Ok(Some(digests.try_into().expect("5 empreintes")))
    })?;

    let Some([md5, sha1, sha256, sha384, sha512]) = outcome else {
        return Ok(None);
    };

    Ok(Some(FileReport {
        path: path.display().to_string(),
        name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        size: total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        hashes: Hashes { md5, sha1, sha256, sha384, sha512 },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn temp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rustchk-test-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn known_vectors_for_abc() {
        let path = temp_file("abc", b"abc");
        let report = hash_file(&path, || false, |_, _| {}).unwrap().unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(report.size, 3);
        assert_eq!(report.hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(report.hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(report.hashes.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            report.hashes.sha384,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            report.hashes.sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn empty_file_and_multi_chunk() {
        let path = temp_file("empty", b"");
        let report = hash_file(&path, || false, |_, _| {}).unwrap().unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(report.hashes.md5, "d41d8cd98f00b204e9800998ecf8427e");

        // Plus d'un bloc : le résultat doit rester celui d'un hachage monolithique.
        let data = vec![0x5au8; CHUNK * 2 + 123];
        let path = temp_file("big", &data);
        let report = hash_file(&path, || false, |_, _| {}).unwrap().unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(report.hashes.sha256, hex::encode(Sha256::digest(&data)));
        assert_eq!(report.hashes.md5, hex::encode(Md5::digest(&data)));
    }

    #[test]
    fn cancellation_returns_none() {
        let path = temp_file("cancel", &vec![1u8; CHUNK * 3]);
        let flag = AtomicBool::new(true);
        let result = hash_file(&path, || flag.load(Ordering::Relaxed), |_, _| {}).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(result.is_none());
    }

    #[test]
    fn rejects_directories_and_missing_files() {
        assert!(hash_file(&std::env::temp_dir(), || false, |_, _| {}).is_err());
        assert!(hash_file(Path::new("n/existe/pas"), || false, |_, _| {}).is_err());
    }
}
