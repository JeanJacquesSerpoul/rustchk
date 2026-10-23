# RustChk

**English** · [Français](README.fr.md)

Verify the checksum of a downloaded file — and check that the checksum file itself is authentic.
A small desktop app written in Rust with [Tauri 2](https://tauri.app) and [Leptos 0.8](https://leptos.dev).

[![CI](https://github.com/JeanJacquesSerpoul/rustchk/actions/workflows/ci.yml/badge.svg)](https://github.com/JeanJacquesSerpoul/rustchk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- **MD5, SHA-1, SHA-256, SHA-384 and SHA-512** computed in a single pass over the file (parallel, with a progress
  bar and a cancel button — about 3.8 s for a 2 GB file on a modern machine).
- **Paste the published checksum**: the algorithm is detected from its length. Accepted formats: `hash`,
  `hash  file`, `sha256:hash`, `SHA256 (file) = hash`, and `certutil` output (bytes separated by spaces).
- **Checksum auto-fill**: if a `file.sha256` (or `.md5`, `.sha1`, `.sha512`…) or a `SHA256SUMS` sits next to the
  download, its checksum is picked up automatically.
- **OpenPGP authentication** of that checksum file (see below).
- **Authenticode signature** of executables and installers (Windows): who signed it, and whether the file was
  modified since.
- **Online malware check** (opt-in): the SHA-256 is looked up on MalwareBazaar and/or VirusTotal.
- **Windows Explorer integration**: a "Verify checksum" entry in the context menu of every file.
- **Drag and drop**, or open from the command line / context menu.
- **Remembers the window size** (and maximized state) between launches.
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

## Publisher signature (Authenticode, Windows)

A checksum and an OpenPGP signature prove that you got the file the vendor published, not that it is harmless.
For executables, installers and scripts (`.exe`, `.msi`, `.dll`, `.ps1`…), RustChk also asks Windows
(`WinVerifyTrust`, as Explorer does) to verify the embedded Authenticode signature:

- **signed by …**: valid signature from an authority trusted by Windows, with the signer and certificate issuer.
  Check that it is the publisher you expect;
- **unsigned**: nothing proves who published the program;
- **rejected**: file modified after signing, certificate revoked, expired without a timestamp, or not issued by a
  trusted authority.

Certificate revocation is checked, so Windows may contact the certificate authority; offline, this is flagged.
Limitation: only signatures embedded in the file are read, so Windows system files signed through a catalog show
up as unsigned. The card is hidden for other file types and on macOS/Linux.

## Online malware check (MalwareBazaar, VirusTotal)

Off by default. In the "Online check" section, tick the box and fill in the key of at least one service:

- [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch): database of malware samples, strong on infostealers
  (Lumma, RedLine, Vidar…). Free Auth-Key at [auth.abuse.ch](https://auth.abuse.ch).
- [VirusTotal](https://www.virustotal.com): result of the last scan by about 70 antivirus engines. Free personal
  key in your account (4 requests/minute, non-commercial use). The file is flagged as malicious from 3 detections
  onwards; below that it is a warning, since an isolated detection is often a false positive.

Once enabled, the **SHA-256 of every file you verify** is sent to these services, never the file or its name.
A file the services have never seen is reported as *unknown*, which does not mean it is safe.
The keys are protected according to the system, and the settings section says which applies:

- **Windows**: stored in `%APPDATA%\app.rustchk\reputation.json`, encrypted with the Windows data protection API
  (DPAPI). Only your Windows account on this machine can decrypt them, so a copy of the file is useless elsewhere and
  the keys must then be entered again.
- **Linux**: kept in your session keyring through Secret Service (GNOME Keyring, KWallet…), encrypted and unlocked
  when you log in. They show up as "RustChk — MalwareBazaar API key" / "… VirusTotal API key" in tools such as
  Seahorse, and `reputation.json` only keeps a marker. Without a reachable keyring (no D-Bus session, minimal window
  manager), they are stored in plain text.
- **macOS**: kept in your login keychain (Keychain), as "app.rustchk" items in Keychain Access. As the app is not
  signed, macOS may ask once to allow access to them after an update.

Keys saved in plain text by an earlier version are protected at the next launch.

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

## Building installers

Same prerequisites as above. Each script builds the UI and the app in release mode, packages it, and copies the
result to `release/` next to a `.sha256` file (which RustChk can verify itself).

| Platform | Command | Output |
| --- | --- | --- |
| Windows | `.\scripts\build-installer.ps1 [-OutDir DIR] [-RunTests]` | NSIS installer `RustChk_<version>_x64-setup.exe` |
| Linux | `scripts/build-appimage.sh [--out DIR] [--test]` | `RustChk_<version>_amd64.AppImage` |

On Linux, install the system libraries first (Debian/Ubuntu):
`sudo apt install build-essential curl wget file libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev libssl-dev librsvg2-dev patchelf`.
Installers are unsigned.

## Continuous integration

[GitHub Actions](.github/workflows/ci.yml) runs on every push to `main` and on every pull request:

| Job | What it checks |
| --- | --- |
| **Format** | `cargo fmt --check` |
| **Linux** (Ubuntu 22.04) · **macOS** · **Windows** | builds the UI with Trunk, `clippy -D warnings`, `cargo test --workspace`, then packages the app (AppImage / `.app` / NSIS installer, the first two through the scripts above) and uploads it as a 7-day artifact |

The tests check that API keys go through each system's real protection (DPAPI, Keychain, Secret Service) rather
than the plain-text fallback; on Linux they run in a D-Bus session with an unlocked gnome-keyring.

The Explorer context-menu integration is Windows-only; on Linux and macOS the app builds and runs without it.
Packages are unsigned.

## Project layout

| Path | Contents |
| --- | --- |
| `core/` | Types and checksum parsing shared by the UI and the backend (pure Rust) |
| `src-tauri/` | Hashing, neighbouring checksum lookup, OpenPGP, Authenticode, online check, Explorer integration, Tauri commands |
| `src/` | Leptos user interface and translations |
| `src-tauri/tests/fixtures/` | Throw-away public keys and signatures generated with GnuPG (no private keys) |

## License

[MIT](LICENSE) © 2026 Jean-Jacques Serpoul
