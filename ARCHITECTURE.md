# kidobo Architecture Specification

## 1. Purpose and Scope

`kidobo` is a host-level firewall maintenance service for Linux systems.

It maintains IP/CIDR blocklists in dedicated `ipset` sets and enforces them
through dedicated `iptables` / `ip6tables` chains.

The system is intentionally **not a resident daemon**. It is designed for
**one-shot execution** (via `systemd` timer, cron, or another scheduler).
Each run performs:

1. Load configuration and sources  
2. Recompute effective blocklist state  
3. Atomically update firewall data structures  
4. Exit  

This document defines behavior and contracts in a language-agnostic way so
the application can be reimplemented in another language.

## 2. Non-Goals

- No packet inspection beyond source-IP matching  
- No distributed coordination across hosts  
- No long-lived process model  
- No direct management of other firewall tools’ chains  
  (UFW and Fail2Ban are treated as coexisting systems)

## 3. External Dependencies and Platform Assumptions

### 3.1 Platform Requirements

Linux host with support for:

- `ipset`
- `iptables`
- `ip6tables` (unless IPv6 disabled)
- `sudo`

### 3.2 Privilege Model

- Firewall operations are executed through `sudo`
- Non-interactive sudoers policy must be configured

### 3.3 Network Dependencies

- Operator-configured remote blocklist URLs
- Optional GitHub meta endpoint: `https://api.github.com/meta`

## 4. Runtime Model

Each invocation is isolated and stateless except for:

- On-disk cache files
- Current firewall state

Core runtime phases:

1. Validate prerequisites  
2. Acquire exclusive lock (non-blocking)  
3. Ensure firewall artifacts and chain wiring  
4. Load and normalize source data  
5. Compute effective IPv4/IPv6 blocklists  
6. Apply updates atomically to `ipset`  
7. Report result and release lock  

If lock acquisition fails, the run terminates immediately.

## 5. Filesystem Layout and Path Resolution

### 5.1 Default System Paths

- Config directory: `/etc/kidobo`
- Config file: `/etc/kidobo/config.toml`
- Data directory: `/var/lib/kidobo`
- Static blocklist: `/var/lib/kidobo/blocklist.txt`
- Cache directory: `/var/cache/kidobo`
- Remote cache: `/var/cache/kidobo/remote`
- Lock file: `/var/cache/kidobo/sync.lock`

### 5.2 `KIDOBO_ROOT` Override

If `KIDOBO_ROOT` is set:

- Config directory: `<root>/config`
- Config file: `<root>/config/config.toml`
- Data directory: `<root>/data`
- Static blocklist: `<root>/data/blocklist.txt`
- Cache directory: `<root>/cache`
- Remote cache: `<root>/cache/remote`
- Lock file: `<root>/cache/sync.lock`

### 5.3 Test Sandbox Behavior

During automated test execution:

If:

- `KIDOBO_TEST_SANDBOX` truthy  
- `KIDOBO_ROOT` unset  
- `KIDOBO_DISABLE_TEST_SANDBOX` unset  

Paths are rooted under:

`<TMPDIR or system temp>/kidobo-tests`

### 5.4 Boolean Environment Values

For boolean environment variables used by kidobo:

- Truthy values (case-insensitive): `1`, `true`, `yes`, `on`
- False values: unset, empty, `0`, `false`, `no`, `off`
- Any other value is treated as false

## 6. Configuration Schema

Configuration format: TOML

Required sections:

- `[ipset]`
- `[safe]` (optional; defaults apply)
- `[remote]` (optional; defaults apply)

### 6.1 `[ipset]`

Fields:

- `set_name` (required)
- `set_name_v6` (optional; default `<set_name>-v6`)
- `enable_ipv6` (default `true`)
- `set_type` (default `hash:net`)
- `hashsize` (default `65536`)
- `maxelem` (default `500000`)
- `timeout` (default `0`)

Validation:

- `hashsize` must be a positive integer and a power of two
- `maxelem` must be an integer in `[1, 500000]`
- `timeout` must be a non-negative integer

### 6.2 `[safe]`

Fields:

- `ips` (list of IP/CIDR; default `[]`)
- `include_github_meta` (default `true`)
- `github_meta_categories` (default `null`)

Category behavior:

- `null` → default categories (`api`, `git`, `hooks`, `packages`)
- empty list → include all categories

### 6.3 `[remote]`

Fields:

- `urls` (list of URL strings; default `[]`)

### 6.4 Config File Selection

1. Explicit path if provided  
2. System config path  
3. If missing and `KIDOBO_ALLOW_REPO_CONFIG_FALLBACK` is truthy:
   use `<repo-root>/config.toml`  
4. Otherwise fail  

`repo-root` is the nearest ancestor directory containing `.git`.

## 7. Public Command Surface

### 7.1 Global Flags

- `--version`
- `--log-level` (`TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`)

### 7.2 Commands

- `init`
- `doctor`
- `sync`
- `flush`
- `lookup [ip | --file <path>]`

### 7.3 Exit Codes

- `0` success  
- `1` operational failure  
- `2` CLI usage error  
- `130` SIGINT  

## 8. Component Responsibilities

### 8.1 Bootstrap

- Parse CLI
- Configure logger
- Dispatch subcommands
- Convert Ctrl-C to exit code 130

### 8.2 `init`

- Ensure directories exist
- Create default config if missing
- Create default blocklist file if missing
- Never overwrite existing files

### 8.3 `doctor`

Emit JSON status and fail if any check not `OK` or `SKIP`.

Checks:

- Config parse
- Binary presence (`sudo`, `ipset`, `iptables`, `iptables-save`, `iptables-restore`, `ip6tables` if enabled)
- File existence
- Cache writability
- `sudo -n` probes

JSON schema:

- Top-level object fields:
  - `overall`: `OK` or `FAIL`
  - `checks`: ordered array of check objects
- Check object fields:
  - `name`: stable identifier string
  - `status`: `OK`, `FAIL`, or `SKIP`
  - `detail`: short human-readable description

### 8.4 Locking

- POSIX `flock`
- Permissions 0600
- Non-blocking acquisition
- Exit if lock held

### 8.5 Source Loaders

Sources:

- Internal static blocklist
- Remote feeds
- GitHub safelist

All normalized into IP/CIDR lists.

### 8.6 Compute Pipeline

- Deduplicate entries
- Collapse overlapping/adjacent networks
- Remove safelist coverage
- Separate IPv4 and IPv6

### 8.7 Firewall Adapter

- Ensure `ipset` exists per family
- Ensure dedicated chain exists
- Ensure single jump from INPUT at position 1
- Ensure DROP rule matches correct set
- Apply updates atomically using temp + swap

### 8.8 Lookup

- Accept single target or file
- `ip` and `--file` are mutually exclusive
- Validate inputs
- Match against cached sources only
- Report target IP, source label(s), and matched source entry line (IP/CIDR)

## 9. Core Data Semantics

### 9.1 Supported Forms

- IPv4 address
- IPv4 CIDR
- IPv6 address
- IPv6 CIDR

Single hosts treated as:

- `/32` (IPv4)
- `/128` (IPv6)

Invalid ingestion lines ignored.
Invalid lookup targets reported as errors.

### 9.2 Family Isolation

IPv4 and IPv6 processed independently for:

- Collapse
- Safelist subtraction
- ipset targets
- Firewall rules

## 10. Canonical Sync Algorithm

### Step A — Prepare

- Load config
- Derive ipset settings
- Determine IPv6 mode
- Determine safelist configuration

### Step B — Ensure Firewall Artifacts

- Ensure IPv4 ipset exists
- Ensure IPv6 ipset exists (if enabled)
- Ensure `kidobo-input` chain exists
- Ensure INPUT jump at position 1
- Ensure DROP rule referencing correct ipset

### Step C — Load Sources

- Internal blocklist
- Remote feeds
- GitHub safelist (if enabled)

### Step D — Deduplicate & Collapse

Example:

- `10.0.0.0/25` + `10.0.0.128/25` → `10.0.0.0/24`

### Step E — Safelist Subtraction

1. Convert safelist networks to intervals
2. Merge intervals
3. Subtract from candidate networks
4. Convert remaining ranges back to minimal CIDRs

Entry count may increase due to carving.

### Step F — Atomic Restore

For each family (IPv6 first):

1. Generate temp set name (≤31 chars)
2. Destroy stale temp set (best effort)
3. Write `ipset restore` script
4. Execute restore
5. Swap temp with destination
6. Destroy temp set

### Step G — Completion

- Re-list final ipset members
- Log counts
- Exit success

## 11. Remote Feed Caching

### 11.1 Cache Naming

For each URL:

- SHA-256(url)
- first 16 hex chars

Files:

- `<hash>.iplist`
- `<hash>.meta.json`
- optional `<hash>.raw`

### 11.2 Metadata

Must contain:

- `url`
- `etag`
- `last_modified`
- `sha256_raw`
- `sha256_iplist`

### 11.3 Conditional Fetch

- Send `If-None-Match`
- Send `If-Modified-Since`

Rules:

- 304 + cache exists → use cache
- 304 + cache missing → unconditional fetch
- 2xx → rewrite cache
- Error → fallback to cache or empty and log warning

### 11.4 Body Size Cap

Default: 32 MiB

Override: `KIDOBO_MAX_HTTP_BODY_BYTES`

### 11.5 Normalization

For each line:

- Trim BOM/whitespace
- Skip blank lines
- Skip `#` comments
- Extract first token
- Keep only valid IP/CIDR

## 12. GitHub Meta Safelist

- Fetch JSON
- Extract IP/CIDR recursively
- Canonicalize
- Deduplicate
- Apply category filtering
- Refuse to widen scope if filtered cache invalid
- Fallback safely

## 13. Lookup Behavior

- No remote fetch
- Use cached sources only
- Invalid targets do not halt valid ones
- Exit failure if any invalid targets
- Match via network overlap
- `ip` and `--file` are mutually exclusive
- For positive matches, output includes:
  - queried target IP
  - blocklist source label
  - matched source entry line (IP/CIDR)

## 14. Flush Behavior

1. Remove all INPUT → kidobo-input jumps
2. Flush + delete chain
3. Destroy ipsets
4. Best-effort on errors

## 15. Firewall Wiring Contract

For each family:

- Chain `kidobo-input` exists
- Exactly one INPUT jump at index 1
- DROP rule matches correct ipset

Deterministic ordering required.

## 16. Concurrency

- Sync serialized by lock file
- Remote fetches concurrent (≤5)
- GitHub fetch concurrent
- Remote fetch failures are per-source soft failures
- Continue remaining fetches after individual failures

## 17. Optional Accelerator Interface

Optional native helpers:

- collapse_networks
- filter_family
- match_ips

Must fallback safely if accelerator fails.

## 18. Logging

- Single logger
- Default INFO
- Log source counts
- Log collapse timing
- Log safelist effect
- Log final ipset counts
- Log doctor JSON report

## 19. Error Handling Strategy

- Fail fast for prerequisites
- Continue best-effort for cleanup
- Prefer stale cache over hard failure
- Explicit non-zero exit codes

## 20. Security Model

- Config is operator-managed
- Cache directory protected
- External feeds treated as hostile
- Strict IP parsing
- Invalid lines ignored
- Response size capped
- Atomic swap prevents half-applied sets

## 21. Rewrite Acceptance Criteria

The rewrite must:

1. Preserve command behavior
2. Preserve config schema and defaults
3. Preserve dual-stack logic
4. Preserve conditional HTTP semantics
5. Preserve safelist carve behavior
6. Preserve atomic swap semantics
7. Preserve firewall wiring contract
8. Preserve lookup cache-only behavior
9. Preserve lock-based single-sync guarantee

## 22. Minimal Behavioral Example

Given:

Internal:

- `10.0.0.0/24`
- `2001:db8::/32`

Remote:

- `10.0.0.128/25`
- `198.51.100.7`

Safelist:

- `10.0.0.0/25`

Result:

- IPv4 collapse → `10.0.0.0/24`
- Safelist carve → `10.0.0.128/25`
- IPv6 unchanged
- Atomic swap into ipsets
- Firewall chain references updated sets

This preserves family separation, safelist carving, and atomic application.

## 23. Build and Quality Gates

The implementation and CI pipeline must enforce:

- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets --all-features`
- `cargo test --doc`
- `cargo check --release --locked`
- `cargo deny check advisories bans licenses sources`
- `cargo audit`
- `cargo llvm-cov --all-features --fail-under-lines 85`
- Agent responses include a proposed commit message for operator review
- Commits are operator-managed; agents do not run `git commit` without explicit operator instruction

Periodic maintenance should include:

- `cargo udeps --all-targets --all-features`

Unsafe code is disallowed unless explicitly approved.
