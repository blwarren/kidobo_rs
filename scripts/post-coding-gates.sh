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

log "running coverage gate"
rustup component add llvm-tools-preview >/dev/null
cargo install --locked cargo-llvm-cov >/dev/null
cargo llvm-cov --all-features --fail-under-lines 85

log "running unused-deps audit"
rustup toolchain install nightly >/dev/null
cargo +nightly udeps --all-targets --all-features

log "post-coding gates complete"
