# kidobo

`kidobo` is a one-shot Linux firewall blocklist manager written in Rust.
It builds IP/CIDR blocklists from local and remote sources, removes safelisted
ranges, and updates `ipset` atomically with deterministic `iptables`/`ip6tables`
wiring.

## What it does

- Parse non-strict IP/CIDR source data (invalid lines are ignored).
- Keep IPv4 and IPv6 processing separate.
- Collapse and deduplicate ranges to reduce rule volume.
- Subtract safelist ranges from blocklist ranges.
- Apply updates atomically with `ipset restore` + `swap`.
- Keep a deterministic firewall chain (`kidobo-input`) in place.
- Cache remote feeds with conditional HTTP fetches (`ETag`/`Last-Modified`).
- Run offline lookups against local + cached sources.

## Requirements

- Linux
- Rust/Cargo 1.93+ (for source builds only)
- `sudo`
- `ipset`
- `iptables`
- `iptables-save`
- `iptables-restore`
- `ip6tables` (only if IPv6 is enabled in config)

`doctor`, `sync`, and `flush` run privileged commands via `sudo -n ...`.
With default system paths (`/etc/kidobo`, `/var/lib/kidobo`, `/var/cache/kidobo`),
`init` is also typically run with `sudo`.

## Install

GitHub release artifacts are currently published for Linux x86_64 only.
For other platforms/architectures, build from source.

Install latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo_rs/main/scripts/install.sh | sudo bash
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo_rs/main/scripts/install.sh | sudo bash -s -- --version v0.3.0
```

Install and initialize in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo_rs/main/scripts/install.sh | sudo bash -s -- --init
```

Build from source (development):

```bash
cargo build --release --locked
./target/release/kidobo --help
```

Periodic maintenance check (matches CI `udeps-audit` workflow):

```bash
cargo +nightly udeps --all-targets --all-features
```

## Quick Start

### 1. Initialize files

```bash
sudo kidobo init
```

This creates missing directories/files and does not overwrite existing config
or blocklist files. `init` prints a summary of created vs unchanged artifacts.
It also creates systemd unit files for periodic sync:

- `/etc/systemd/system/kidobo-sync.service`
- `/etc/systemd/system/kidobo-sync.timer`

With default system paths, `init` also runs:

- `systemctl daemon-reload`
- `systemctl reset-failed kidobo-sync.service`
- `systemctl enable --now kidobo-sync.timer`

When `KIDOBO_ROOT` is set, unit files are written under
`$KIDOBO_ROOT/systemd/system/` instead, and `systemctl` commands are skipped.

### 2. Edit config

Default config file:

```text
/etc/kidobo/config.toml
```

Example:

```bash
sudoedit /etc/kidobo/config.toml
```

### 3. Add local blocklist entries (optional)

Default local blocklist file:

```text
/var/lib/kidobo/blocklist.txt
```

Example:

```bash
echo "203.0.113.0/24" | sudo tee -a /var/lib/kidobo/blocklist.txt
```

### 4. Check the environment

```bash
sudo kidobo doctor
```

`doctor` prints a JSON report and exits non-zero if required checks fail.

### 5. Apply blocklists

```bash
sudo kidobo sync
```

### 6. Enable periodic sync manually (optional)

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kidobo-sync.timer
```

### 7. Check whether an IP would match

```bash
kidobo lookup 203.0.113.7
kidobo lookup --file targets.txt
```

### 8. Remove Kidobo firewall/ipset artifacts (optional)

```bash
sudo kidobo flush
```

To clear only remote feed cache files without touching firewall/ipset state:

```bash
sudo kidobo flush --cache-only
```

## Configuration

Example config:

```toml
[ipset]
set_name = "kidobo"
set_name_v6 = "kidobo-v6"
enable_ipv6 = true
chain_action = "DROP"
set_type = "hash:net"
hashsize = 65536
maxelem = 500000
timeout = 0

[safe]
ips = []
include_github_meta = true
github_meta_url = "https://api.github.com/meta"
# github_meta_categories = ["api", "git", "hooks", "packages"]

[remote]
timeout_secs = 30
urls = []
```

Key fields:

- `[ipset]`
  - `set_name` required
  - `set_name_v6` optional, defaults to `"<set_name>-v6"`
  - `enable_ipv6` default `true`
  - `chain_action` optional, `DROP` (default) or `REJECT`
  - `maxelem` must be in `[1, 500000]`
- `[safe]`
  - `ips` static safelist entries
  - `include_github_meta` default `true`
  - `github_meta_url` default `https://api.github.com/meta`
  - `github_meta_categories`:
    - omitted: default categories (`api`, `git`, `hooks`, `packages`)
    - `[]`: all categories
    - explicit list: only those categories
- `[remote]`
  - `timeout_secs` request timeout for each remote HTTP fetch (default `30`, range `[1, 3600]`)
  - `urls` list of remote feed URLs

Invalid or missing required config causes command failure.

## Paths and Environment

Default system paths:

- config dir: `/etc/kidobo`
- config file: `/etc/kidobo/config.toml`
- data dir: `/var/lib/kidobo`
- blocklist file: `/var/lib/kidobo/blocklist.txt`
- cache dir: `/var/cache/kidobo`
- remote cache dir: `/var/cache/kidobo/remote`
- lock file: `/var/cache/kidobo/sync.lock`
- systemd service: `/etc/systemd/system/kidobo-sync.service`
- systemd timer: `/etc/systemd/system/kidobo-sync.timer`

Useful environment variables:

- `KIDOBO_ROOT`
  - Relocates config/data/cache under one writable root.
- `KIDOBO_ALLOW_REPO_CONFIG_FALLBACK`
  - Truthy values (`1`, `true`, `yes`, `on`) allow config fallback to
    `<repo-root>/config.toml` when the primary config is missing.
- `KIDOBO_MAX_HTTP_BODY_BYTES`
  - Overrides max remote response body size (default: `33554432` bytes).

## Commands

```text
kidobo init
kidobo doctor
kidobo sync
kidobo flush [--cache-only]
kidobo lookup [ip | --file <path>]
```

Global flags:

- `--version`
- `--log-level <trace|debug|info|warn|error>`

## Lookup Output

Each match is printed as tab-separated fields:

```text
<queried-target-ip-or-cidr>    <source-label>    <matched-source-entry>
```

For remote cached sources, `<source-label>` is the original source URL from
cache metadata.

Lookup does not fetch remote data; it uses local and cached sources only.

## License

MIT (see `LICENSE`).
