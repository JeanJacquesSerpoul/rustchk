#!/usr/bin/env bash
#
# Builds the Linux AppImage of RustChk.
#
# Builds the Leptos UI (Trunk) and the Tauri app in release mode, packages them as an AppImage,
# then copies it to OUT_DIR together with its SHA-256 checksum file (sha256sum format, readable by
# RustChk itself).
#
# Requirements: Rust with the wasm32-unknown-unknown target, Trunk, the Tauri CLI
# (`cargo install trunk tauri-cli`, or `npm i -g @tauri-apps/cli@2`) and the Tauri system libraries.
# On Debian/Ubuntu:
#   sudo apt install build-essential curl wget file libwebkit2gtk-4.1-dev libgtk-3-dev \
#        libxdo-dev libssl-dev librsvg2-dev patchelf
#
# Usage: scripts/build-appimage.sh [--out DIR] [--test] [-h|--help]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/release"
RUN_TESTS=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [--out DIR] [--test]

  --out DIR   Where to copy the AppImage (default: $ROOT/release)
  --test      Run 'cargo test --workspace' before packaging
  -h, --help  Show this help
EOF
}

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\033[36m==> %s\033[0m\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT_DIR="$2"; shift 2 ;;
    --test) RUN_TESTS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

# --- Prerequisites -------------------------------------------------------------------------------

step "Checking prerequisites"
[ "$(uname -s)" = "Linux" ] || die "AppImages can only be built on Linux (found $(uname -s))."

command -v cargo >/dev/null || die "cargo not found. Install Rust from https://rustup.rs"
command -v trunk >/dev/null || die "trunk not found. Run: cargo install trunk"

if command -v rustup >/dev/null; then
  rustup target list --installed | grep -qx wasm32-unknown-unknown \
    || die "the wasm32-unknown-unknown target is missing. Run: rustup target add wasm32-unknown-unknown"
fi

# `cargo tauri` (cargo install tauri-cli) or the `tauri` command (npm i -g @tauri-apps/cli).
if cargo tauri --version >/dev/null 2>&1; then
  TAURI=(cargo tauri)
elif command -v tauri >/dev/null; then
  TAURI=(tauri)
else
  die "Tauri CLI not found. Run: cargo install tauri-cli   (or: npm i -g @tauri-apps/cli@2)"
fi

if command -v pkg-config >/dev/null; then
  pkg-config --exists webkit2gtk-4.1 gtk+-3.0 librsvg-2.0 \
    || die "missing system libraries (webkit2gtk-4.1, gtk3, librsvg). On Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libxdo-dev libssl-dev patchelf"
else
  die "pkg-config not found. On Debian/Ubuntu: sudo apt install pkg-config"
fi

# linuxdeploy's bundled `strip` fails on recent distributions (.relr sections).
export NO_STRIP="${NO_STRIP:-true}"
# Without FUSE (containers, CI), run the AppImage tooling by extraction instead of mounting.
if [ ! -e /dev/fuse ]; then
  export APPIMAGE_EXTRACT_AND_RUN="${APPIMAGE_EXTRACT_AND_RUN:-1}"
fi
# Trunk rejects NO_COLOR=1, which some terminals set.
if [ "${NO_COLOR:-}" = "1" ]; then export NO_COLOR=true; fi

cd "$ROOT"

# --- Tests (optional) ----------------------------------------------------------------------------

if [ "$RUN_TESTS" -eq 1 ]; then
  step "Building the UI and running the tests"
  # The Tauri backend embeds dist/ at compile time: it must exist before `cargo test`.
  trunk build --release
  cargo test --workspace
fi

# --- AppImage ------------------------------------------------------------------------------------

step "Building the AppImage (this takes a few minutes the first time)"
"${TAURI[@]}" build --bundles appimage

APPIMAGE="$(ls -t "$TARGET_DIR"/release/bundle/appimage/*.AppImage 2>/dev/null | head -n 1 || true)"
[ -n "$APPIMAGE" ] || die "no AppImage found in $TARGET_DIR/release/bundle/appimage"

# --- Output --------------------------------------------------------------------------------------

step "Copying to $OUT_DIR"
mkdir -p "$OUT_DIR"
NAME="$(basename "$APPIMAGE")"
cp -f "$APPIMAGE" "$OUT_DIR/$NAME"
chmod +x "$OUT_DIR/$NAME"

# `hash  name`: the format `sha256sum -c` and RustChk both read.
(cd "$OUT_DIR" && sha256sum "$NAME" > "$NAME.sha256")

echo
printf 'AppImage : %s (%s)\n' "$OUT_DIR/$NAME" "$(du -h "$OUT_DIR/$NAME" | cut -f1)"
printf 'SHA-256  : %s\n' "$(cut -d' ' -f1 "$OUT_DIR/$NAME.sha256")"
printf 'Checksum : %s\n' "$OUT_DIR/$NAME.sha256"
