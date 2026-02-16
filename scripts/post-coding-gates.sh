#!/usr/bin/env bash
set -euo pipefail

log() {
    printf '[post-coding] %s\n' "$1"
}

log "running format gate"
cargo fmt --all --check

log "running clippy gate"
cargo clippy --all-targets --all-features -- -D warnings

log "running functional test suite"
cargo test --all-targets --all-features

log "running doc tests"
cargo test --doc

log "running release check"
cargo check --release --locked

log "running supply-chain checks"
cargo deny check advisories bans licenses sources
cargo audit

log "check for unused dependencies"
rustup toolchain install nightly --component rust-src
cargo +nightly install --locked cargo-udeps
cargo +nightly udeps --all-targets --all-features

log "running coverage gate"
cargo llvm-cov --all-features --fail-under-lines 85

log "post-coding gates complete"
