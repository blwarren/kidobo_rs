#!/usr/bin/env bash
set -euo pipefail

echo "[pre-commit] cargo fmt --all --check"
cargo fmt --all --check

echo "[pre-commit] cargo clippy --all-targets --all-features -- -D warnings"
cargo clippy --all-targets --all-features -- -D warnings

echo "[pre-commit] cargo test --lib --bins --tests --all-features"
cargo test --lib --bins --tests --all-features
