# kidobo

`kidobo` is a one-shot Linux firewall blocklist manager.
It builds IPv4/IPv6 blocklists from local and remote sources, subtracts safelist
entries, and updates `ipset` atomically with deterministic
`iptables`/`ip6tables` wiring.

## Requirements

- Linux
- `sudo`
- `ipset`
- `iptables`, `iptables-save`, `iptables-restore`
- `ip6tables` (only when IPv6 is enabled)

`doctor`, `sync`, and `flush` run privileged commands via `sudo -n ...`.
With default system paths, `init` is also typically run with `sudo`.

## Install

Release artifacts are currently published for Linux `x86_64`.
For other targets, build from source.

Install latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.5.3
```

Install and initialize in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --init
```

Uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --uninstall
```

Build from source:

```bash
cargo build --release --locked
./target/release/kidobo --help
```

## Quick Start

1. Initialize files:

```bash
sudo kidobo init
```

2. Edit config:

```bash
sudoedit /etc/kidobo/config.toml
```

3. (Optional) add local entries:

```bash
echo "203.0.113.0/24" | sudo tee -a /var/lib/kidobo/blocklist.txt
```

4. Check environment:

```bash
sudo kidobo doctor
```

5. Apply blocklists:

```bash
sudo kidobo sync
```

6. Check whether targets match (offline):

```bash
kidobo lookup 203.0.113.7
kidobo lookup --file targets.txt
```

7. Remove kidobo firewall/ipset artifacts (optional):

```bash
sudo kidobo flush
sudo kidobo flush --cache-only
```

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

Logging format:

- `KIDOBO_LOG_FORMAT=auto|human|journal` (default `auto`)
- `auto` uses `journal` under systemd or when stderr is non-TTY, and `human`
  for interactive TTY runs
- `KIDOBO_LOG_COLOR=auto|always|never` controls color in human format
  (default `auto`)
- In `auto`, human format uses colored level labels on interactive TTY output
  and respects `NO_COLOR`

## Minimal Config

`/etc/kidobo/config.toml`:

```toml
[ipset]
set_name = "kidobo"

[safe]
ips = []
include_github_meta = true
github_meta_url = "https://api.github.com/meta"

[remote]
timeout_secs = 30
urls = []
```

Useful options:

- `ipset.set_name_v6`: optional, defaults to `<set_name>-v6`
- `ipset.enable_ipv6`: default `true`
- `ipset.chain_action`: `DROP` (default) or `REJECT`
- `ipset.maxelem`: range `[1, 500000]`
- `remote.timeout_secs`: range `[1, 3600]`

## Defaults

- Config file: `/etc/kidobo/config.toml`
- Local blocklist: `/var/lib/kidobo/blocklist.txt`
- Cache dir: `/var/cache/kidobo`
- Systemd units:
  - `/etc/systemd/system/kidobo-sync.service`
  - `/etc/systemd/system/kidobo-sync.timer`

`kidobo init` creates missing files and systemd units.
At default paths it also runs `systemctl daemon-reload` and enables
`kidobo-sync.timer`, and writes `KIDOBO_LOG_FORMAT=journal` into
`kidobo-sync.service`.

## Notes

- `lookup` does not fetch remote data; it only uses local and cached sources.
- `KIDOBO_ROOT` relocates config/data/cache paths under a custom root.

## License

MIT (see `LICENSE`).
