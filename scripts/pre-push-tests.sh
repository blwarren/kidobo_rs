#!/usr/bin/env bash
set -euo pipefail

echo "[pre-push] cargo test --lib --bins --tests --all-features"
cargo test --lib --bins --tests --all-features
