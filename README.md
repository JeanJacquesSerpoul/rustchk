# RustChk

**English** · [Français](README.fr.md)

Verify the checksum of a downloaded file — and check that the checksum file itself is authentic.
A small desktop app written in Rust with [Tauri 2](https://tauri.app) and [Leptos 0.8](https://leptos.dev).

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- **MD5, SHA-1, SHA-256, SHA-384 and SHA-512** computed in a single pass over the file (parallel, with a progress
  bar and a cancel button — about 3.8 s for a 2 GB file on a modern machine).
- **Paste the published checksum**: the algorithm is detected from its length. Accepted formats: `hash`,
  `hash  file`, `sha256:hash`, `SHA256 (file) = hash`, and `certutil` output (bytes separated by spaces).
- **Checksum auto-fill**: if a `file.sha256` (or `.md5`, `.sha1`, `.sha512`…) or a `SHA256SUMS` sits next to the
  download, its checksum is picked up automatically.
- **OpenPGP authentication** of that checksum file (see below).
- **Windows Explorer integration**: a "Verify checksum" entry in the context menu of every file.
- **Drag and drop**, or open from the command line / context menu.
- **English and French** interface, switchable on the fly.

## Authenticating the checksum file (OpenPGP)

A checksum protects against a corrupted download, not against a file replaced *together with* its checksum.
When the checksum comes from a checksum file, RustChk verifies its OpenPGP signature with
[rPGP](https://crates.io/crates/pgp) (pure Rust — GnuPG is not required):

- a neighbouring detached signature: `SHA256SUMS.asc`, `.sig`, `.gpg`, `.sign` or `.pgp` (binary or ASCII-armored);
- or a clear-signed file (`-----BEGIN PGP SIGNED MESSAGE-----`). Only the text inside the signed block is read;
  text added before or after the signature makes the whole file rejected.

Outcomes: **authentic** (signer, key ID, date, and the key fingerprint to compare with the vendor's), **unknown
key**, **signature rejected** (content modified, key revoked) or **no signature**. A rejected signature always
overrides "file matches".

Only the public keys you import into the app's keyring (`%APPDATA%\app.rustchk\keys`, "OpenPGP keyring" section)
are trusted. Nothing is downloaded and no key is read from the download folder: get the key from the vendor's
official website and compare its fingerprint before importing it.

Limitations: no web of trust and no keyserver lookup; a key that has expired is only flagged (as a warning) when
it had already expired at signing time.

## Explorer integration (Windows)

Adds "Verify checksum (RustChk)" to the context menu of all files, under
`HKCU\Software\Classes\*\shell\RustChk` (no administrator rights needed). On Windows 11 it appears under
"Show more options" (Shift+F10).

- Use the checkbox at the bottom of the app, or
- `rustchk.exe --register-shell [--lang fr|en]` / `rustchk.exe --unregister-shell`, or
- let the NSIS installer do it (`src-tauri/windows/hooks.nsh`); it is removed on uninstall.

The menu label follows the interface language.

## Languages

Use the **FR | EN** switch at the top right; the choice is remembered. On first launch the system language is used
(French if it is French, English otherwise). All texts live in [`src/i18n.rs`](src/i18n.rs); the backend returns
structured errors that the UI translates. To add a language, add a variant to `Lang` in `core/` — the compiler
points out every missing text.

## Build from source

Requirements: [Rust](https://rustup.rs), the `wasm32-unknown-unknown` target, [Trunk](https://trunkrs.dev),
the [Tauri CLI](https://tauri.app/start/prerequisites/), and the Tauri prerequisites for your platform
(WebView2 and the MSVC build tools on Windows).

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk tauri-cli
cargo tauri dev        # runs trunk serve + the app
cargo tauri build      # installer in target/release/bundle/nsis
cargo test --workspace # unit tests
```

If `trunk` fails under PowerShell with `invalid value '1' for '--no-color'`, set `NO_COLOR=true` first.

## Project layout

| Path | Contents |
| --- | --- |
| `core/` | Types and checksum parsing shared by the UI and the backend (pure Rust) |
| `src-tauri/` | Hashing, neighbouring checksum lookup, OpenPGP, Explorer integration, Tauri commands |
| `src/` | Leptos user interface and translations |
| `src-tauri/tests/fixtures/` | Throw-away public keys and signatures generated with GnuPG (no private keys) |

## License

[MIT](LICENSE) © 2026 Jean-Jacques Serpoul
