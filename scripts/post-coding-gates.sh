#!/usr/bin/env bash
set -euo pipefail

log() {
    printf '[post-coding] %s\n' "$1"
}

log "running format gate"
cargo fmt --all

log "running clippy gate"
cargo clippy --all-targets --all-features -- -D warnings

log "running functional test suite"
cargo test --all-targets --all-features

log "running release build"
cargo build --release --locked

log "running supply-chain checks"
cargo deny check advisories bans licenses sources

log "running coverage gate"
scripts/check-critical-coverage.sh

log "post-coding gates complete"
