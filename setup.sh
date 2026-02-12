#!/usr/bin/env bash
# RevaultPass - build release binary
set -e
cd "$(dirname "$0")"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust not found. Install from https://rustup.rs"
  exit 1
fi
cargo build --release
echo "Done. Run: ./target/release/revaultpass help"
echo "Or: cp target/release/revaultpass ~/.local/bin/"
