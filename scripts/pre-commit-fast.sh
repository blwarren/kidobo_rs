#!/usr/bin/env bash
set -euo pipefail

echo "[pre-commit] cargo fmt --all --check"
cargo fmt --all --check

echo "[pre-commit] cargo clippy --all-targets --all-features -- -D warnings"
cargo clippy --all-targets --all-features -- -D warnings

echo "[pre-commit] normalize release notes markdown"
./scripts/changelog/format-release-notes.sh

echo "[pre-commit] regenerate CHANGELOG.md"
./scripts/changelog/generate.sh

if ! git diff --quiet -- CHANGELOG.md release-notes; then
  echo "[pre-commit] Release notes and/or CHANGELOG.md were rewritten; stage updates and re-run commit."
  git --no-pager diff -- CHANGELOG.md release-notes
  exit 1
fi
