# kidobo_rs (`kidobo` CLI)

`kidobo` is a one-shot Linux firewall blocklist manager written in Rust.
It builds blocklists from local and remote sources, carves out safelisted
networks, and applies updates atomically to `ipset` with deterministic
`iptables`/`ip6tables` wiring.

The crate is currently named `kidobo_rs`; the installed binary is `kidobo`.

## What it does

- Parses non-strict IP/CIDR source data (ignores invalid lines).
- Separates IPv4 and IPv6 processing.
- Deduplicates, collapses, and safelist-subtracts networks.
- Applies updates via atomic `ipset restore` + `swap`.
- Enforces a deterministic firewall chain: `kidobo-input`.
- Caches remote feeds with conditional HTTP requests (`ETag`/`Last-Modified`).
- Provides offline lookup against local blocklist + cached remote sources.

## Requirements

- Linux with:
  - `sudo`
  - `ipset`
  - `iptables`
  - `iptables-save`
  - `iptables-restore`
  - `ip6tables` (only when IPv6 is enabled in config)
- Rust stable toolchain (for building from source)

Runtime commands that touch firewall state (`doctor` probes, `sync`, `flush`)
run commands through `sudo -n ...` and therefore require non-interactive
privilege (for example NOPASSWD sudo policy) or execution as a context where
`sudo -n` succeeds.

With default system paths (`/etc/kidobo`, `/var/lib/kidobo`, `/var/cache/kidobo`),
`init`, `doctor`, `sync`, and `flush` are typically run with `sudo`.

## Install

Install from crates.io (recommended once published):

```bash
cargo install --locked --bin kidobo kidobo_rs
```

Install a prebuilt Linux x86_64 binary from GitHub Releases:

```bash
version="v0.1.0"
archive="kidobo-${version}-linux-x86_64.tar.gz"
base_url="https://github.com/blwarren/kidobo_rs/releases/download/${version}"

curl -fsSL -O "${base_url}/${archive}"
curl -fsSL -O "${base_url}/SHA256SUMS"
sha256sum --check SHA256SUMS
tar -xzf "${archive}"
sudo install -m 0755 "kidobo-${version}-linux-x86_64/kidobo" /usr/local/bin/kidobo
```

Build from source:

```bash
cargo build --release --locked
./target/release/kidobo --help
```

## Quick Start

### 1. Initialize files

```bash
sudo kidobo init
```

This creates missing directories/files and does not overwrite existing config
or blocklist files.

### 2. Edit config

Default config path:

```text
/etc/kidobo/config.toml
```

Example:

```bash
sudoedit /etc/kidobo/config.toml
```

Minimal generated template:

```toml
[ipset]
set_name = "kidobo"

[safe]
ips = []
include_github_meta = true
# github_meta_categories = ["api", "git", "hooks", "packages"]

[remote]
urls = []
```

### 3. Run environment checks

```bash
sudo kidobo doctor
```

`doctor` prints JSON and exits non-zero if required checks fail.

### 4. Apply blocklist

```bash
sudo kidobo sync
```

### 5. Query matches

```bash
kidobo lookup 203.0.113.7
kidobo lookup --file ./targets.txt
```

Output format (tab-separated):

```text
<queried-target-ip-or-cidr>    <source-label>    <matched-source-entry>
```

## Safe Local Sandbox Example (No System Paths)

For local experiments that should not write `/etc`, `/var/lib`, or `/var/cache`,
set `KIDOBO_ROOT`:

```bash
export KIDOBO_ROOT="$PWD/.kidobo-dev"
kidobo init
```

No `sudo` is required in this sandboxed flow as long as `KIDOBO_ROOT` points to
a user-writable location.

This relocates config/data/cache under:

```text
$KIDOBO_ROOT/config
$KIDOBO_ROOT/data
$KIDOBO_ROOT/cache
```

Example local-only lookup flow:

```bash
printf "203.0.113.0/24\n" > "$KIDOBO_ROOT/data/blocklist.txt"
kidobo lookup 203.0.113.7
```

Note: `sync` and `flush` still operate on real firewall/ipset state and need
working `sudo -n` permissions.

## Commands

Command surface (invocation may still require `sudo` depending on path and
permission context):

```text
kidobo init
kidobo doctor
kidobo sync
kidobo flush
kidobo lookup [ip | --file <path>]
```

Global flags:

- `--version`
- `--log-level <trace|debug|info|warn|error>`

## Exit Codes

- `0`: success
- `1`: operational failure
- `2`: CLI usage error
- `130`: interrupted by SIGINT

## Path Resolution

Default system paths:

- config dir: `/etc/kidobo`
- config file: `/etc/kidobo/config.toml`
- data dir: `/var/lib/kidobo`
- blocklist file: `/var/lib/kidobo/blocklist.txt`
- cache dir: `/var/cache/kidobo`
- remote cache dir: `/var/cache/kidobo/remote`
- lock file: `/var/cache/kidobo/sync.lock`

Environment controls:

- `KIDOBO_ROOT`:
  - Overrides the root for config/data/cache layout.
- `KIDOBO_ALLOW_REPO_CONFIG_FALLBACK`:
  - Truthy values (`1`, `true`, `yes`, `on`, case-insensitive) enable fallback
    config at `<repo-root>/config.toml` when primary config is missing.
  - This changes config file location only; data/cache remain under resolved base
    paths.
- `KIDOBO_TEST_SANDBOX`:
  - Truthy enables temp-root fallback at `<temp-dir>/kidobo-tests`.
- `KIDOBO_DISABLE_TEST_SANDBOX`:
  - Presence disables the test sandbox behavior.

## Configuration Reference

```toml
[ipset]
set_name = "kidobo"       # required
set_name_v6 = "kidobo-v6" # optional; defaults to "<set_name>-v6"
enable_ipv6 = true        # default: true
set_type = "hash:net"     # default: "hash:net"
hashsize = 65536          # default: 65536, must be power-of-two >= 1
maxelem = 500000          # default: 500000, range: 1..500000
timeout = 0               # default: 0

[safe]
ips = []                  # static safelist entries
include_github_meta = true
# github_meta_categories behavior:
# - omitted: default categories ["api", "git", "hooks", "packages"]
# - []: all categories
# - ["api", "hooks"]: explicit categories

[remote]
urls = []                 # remote IP/CIDR feed URLs
```

Invalid or missing required config causes failure.

## Sync Behavior (High-Level)

`sync` performs this sequence:

1. Load config
2. Acquire non-blocking lock
3. Ensure ipset sets and firewall wiring exist
4. Load internal blocklist + remote feeds + safelist inputs
5. Subtract safelist ranges
6. Deduplicate/collapse per family
7. Atomic `ipset restore` + `swap`
8. Best-effort temp set cleanup
9. Log source and final counts
10. Release lock (RAII drop)

Remote source failures are soft-fail per source (warn + continue).

## Firewall and Ipset Details

- Chain name: `kidobo-input`
- Exactly one `INPUT -> kidobo-input` jump is kept at position 1.
- Chain is flushed and repopulated with:
  - `-m set --match-set <set_name> src -j DROP`
- Atomic set replacement uses a randomized temp set suffix with enforced max
  name length 31 chars.
- Temp set destroy is always attempted (best effort).

## HTTP Cache Behavior

Per remote URL:

- Cache key: `sha256(url)` first 16 hex chars
- Files:
  - `<hash>.iplist` (normalized IP/CIDR lines)
  - `<hash>.meta.json` (etag/last-modified/checksums)
  - `<hash>.raw` (raw response bytes)
- Conditional fetch uses `If-None-Match` and `If-Modified-Since`.
- `304` uses cache when valid.
- Network errors, non-2xx, or oversize body fall back to cache.
- Successful responses are normalized into canonical IP/CIDR lines; invalid
  lines are discarded.

Body-size cap:

- Default: `33554432` (32 MiB)
- Override via `KIDOBO_MAX_HTTP_BODY_BYTES` (positive integer)

## GitHub Meta Safelist

When `safe.include_github_meta = true`, `sync` fetches GitHub metadata from:

```text
https://api.github.com/meta
```

It extracts IP/CIDR values recursively and applies category filtering mode.
If cache scope is incompatible with the requested category filter, data is not
widened from stale cache.

## Lookup Semantics

- No remote fetch is performed.
- Sources are loaded from:
  - internal blocklist file
  - cached remote `*.iplist` files
- Targets are validated strictly.
- Invalid targets are reported, processing continues, and command exits with
  failure if any invalid target was provided.
- `ip` and `--file` are mutually exclusive.

## Logging

- Single global logger (`env_logger`)
- Default level: `INFO`
- Override with `--log-level`
- Includes sync source counts, final counts, and doctor JSON payload.

## Development

Install repo hooks:

```bash
git config core.hooksPath .githooks
```

Fast local pre-commit checks:

```bash
scripts/pre-commit-fast.sh
```

Full local gates:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --doc
cargo check --release --locked
cargo deny check advisories bans licenses sources
cargo audit
cargo llvm-cov --all-features --fail-under-lines 85
cargo +nightly udeps --all-targets --all-features
```

CI workflows:

- `.github/workflows/ci.yml`
- `.github/workflows/udeps-audit.yml`
- `.github/workflows/release.yml`

## License

MIT (see `LICENSE`).
