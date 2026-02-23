# kidobo

`kidobo` is a one-shot Linux firewall blocklist manager.
It builds IPv4/IPv6 blocklists from local and remote sources, subtracts
safelist entries, and updates `ipset` atomically with deterministic
`iptables`/`ip6tables` wiring.

## Features

- Easily manage and update both local and remote IP/CIDR blocklists.
- Utilizes ipset to harness the efficiency of the Linux kernel in enforcing blocklists.
- Automatic dedupe and consolidation of blocklists before ipset creation.
- Sync happens **fast**: in testing on a Linode Nanode (Single core CPU VM with 1 GB RAM)
  updates involving multiple blocklists totalling 400,000 lines happen in less than
  five seconds.
- Stay in control: identify safe IP's that are carved out of blocklists.
- Local blocklist entries can be managed through manual editing of text
  file or through use of CLI ban/unban commands.

## Install

Release binaries are currently published for Linux x86_64.

No testing has been performed on other CPU architectures, but feel free to run the test suite and build from source when using this on other platforms.

Install latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.8.0
```

Install and initialize in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --init
```

Uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --uninstall
```

Security note: piping a script to `sudo bash` is convenient, but you should
review the script (and pin a version) if you need a stricter install policy.

## Quick Start

Initialize default files and (optionally) systemd units:

```bash
sudo kidobo init
```

Configure your sources and safelist:

```bash
sudoedit /etc/kidobo/config.toml
```

Add local entries (optional):

Use commands:

```bash
kidobo ban 203.0.113.7
kidobo unban 203.0.113.7
kidobo ban --asn 213412
kidobo unban --asn AS213412
```

Or edit the local blocklist file directly:

```bash
echo "203.0.113.0/24" | sudo tee -a /var/lib/kidobo/blocklist.txt
```

Check prerequisites and system wiring:

```bash
sudo kidobo doctor
```

Apply blocklists to `ipset` and firewall rules:

```bash
sudo kidobo sync
```

Re-apply after local blocklist changes:

```bash
sudo kidobo sync
```

Check whether targets match (offline):

```bash
kidobo lookup 203.0.113.7
kidobo lookup --file targets.txt
# analyze overlap vs cached remote sources only (offline)
kidobo analyze overlap
# print optional reduction candidate lists
kidobo analyze overlap --print-fully-covered-local --print-reduced-local
# automatically remove fully covered local entries
kidobo analyze overlap --apply-fully-covered-local
```

Remove kidobo firewall/ipset artifacts (optional):

```bash
sudo kidobo flush
sudo kidobo flush --cache-only
```

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
cache_stale_after_secs = 86400
urls = []

[asn]
banned = []
cache_stale_after_secs = 86400
```

Useful options:

- `ipset.set_name_v6`: optional, defaults to `<set_name>-v6`
- `ipset.enable_ipv6`: default `true`
- `ipset.chain_action`: `DROP` (default) or `REJECT`
- `ipset.maxelem`: range `[1, 500000]`
- `remote.timeout_secs`: range `[1, 3600]`
- `remote.cache_stale_after_secs`: remote cache staleness threshold for overlap
  analysis warnings (default `86400`, range `[1, 604800]`)
- `asn.banned`: ASN bans that are resolved to prefixes during `sync`
- `asn.cache_stale_after_secs`: ASN prefix cache refresh threshold
  (default `86400`, range `[1, 604800]`)

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

- `ban` and `unban` modify local source state only:
  blocklist entries for IP/CIDR targets and config `[asn].banned` for ASN targets.
  Run `sync` to apply changes to firewall/ipset runtime state.
- `lookup` runs only against cached blocklists - run `sync` first if you need latest list
  data.
- `analyze overlap` is offline-only and warns when cached remote
  `.iplist` files are older than `remote.cache_stale_after_secs`.
- `analyze overlap --apply-fully-covered-local` removes local entries that are
  fully covered by cached remote union; run `kidobo sync` afterward to apply.
- `KIDOBO_ROOT` relocates config/data/cache paths under a custom root.

## License

MIT (see `LICENSE`).
