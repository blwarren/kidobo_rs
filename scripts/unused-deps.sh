rustup toolchain install nightly --component rust-src
cargo +nightly install --locked cargo-udeps
cargo +nightly udeps --all-targets --all-features
