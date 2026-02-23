#!/usr/bin/env bash
set -euo pipefail

echo "[pre-commit] cargo fmt --all --check"
cargo fmt --all --check

echo "[pre-commit] cargo clippy --all-targets --all-features -- -D warnings"
cargo clippy --all-targets --all-features -- -D warnings

echo "[pre-commit] regenerate CHANGELOG.md"
./scripts/changelog/generate.sh

if ! git diff --quiet -- CHANGELOG.md; then
  echo "[pre-commit] CHANGELOG.md was regenerated; stage it and re-run commit."
  git --no-pager diff -- CHANGELOG.md
  exit 1
fi
