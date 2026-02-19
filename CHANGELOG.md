# Changelog

## [Unreleased]

### Fixed

- `kidobo sync` now writes generated `ipset restore` scripts through buffered I/O, reducing kernel write-call overhead introduced by per-line restore emission while preserving atomic swap behavior.

## [0.5.2] - 2026-02-19

### Changed

- `kidobo sync` now uses a fast local blocklist-change check (`size` + `mtime`) and skips the canonicalize/collapse rewrite pass when the local blocklist file is unchanged since the last sync.

## [0.5.1] - 2026-02-19

### Changed

- `kidobo lookup` now streams matches directly to output while preserving deterministic ordering, instead of accumulating all matches in memory first. This reduces peak RAM use and avoids large global sort/dedup overhead on large target/source combinations.
- `kidobo sync` now uses lightweight `ipset list <set> -terse` probing for set existence checks (with compatibility fallback), avoiding expensive full-set listings in the common path.
- Remote sync fetch worker selection is now CPU-aware (`available_parallelism`) while still capped by `MAX_REMOTE_FETCH_WORKERS`, reducing oversubscription pressure on single-core hosts.
- Ipset restore script generation now skips redundant sort/dedup work when entries are already sorted and unique, reducing CPU and allocation overhead on the sync hot path.
- Remote cache normalization now formats canonical CIDRs without building an intermediate `Vec<String>`, reducing temporary allocations during source processing.

## [0.5.0] - 2026-02-18

### Added

- `scripts/install.sh` now supports `--uninstall` for full teardown: best-effort flush of firewall/ipset state, systemd timer cleanup, removal of kidobo config/data/cache directories, and removal of the installed binary from `KIDOBO_INSTALL_DIR` (default `/usr/local/bin`).

### Changed

- TLS backend selection now uses `reqwest` with `rustls-no-provider` and an explicit `rustls` `ring` provider, avoiding `aws-lc`/OpenSSL-licensed transitive crypto code while preserving offline behavior and command surface.
- Updated `Cargo.lock` to use `bumpalo` `3.20.1` (from `3.20.0`) to clear a yanked transitive dependency warning in supply-chain checks.
- Core interval carving and collapse paths now avoid redundant merge/sort passes and per-fragment temporary vectors, reducing CPU and allocation pressure during `sync`.
- `kidobo sync` now streams effective CIDRs directly into `ipset restore` generation (without building intermediate `Vec<String>` entries), reducing peak memory use for large sets.
- Remote source fetch workers now use lock-free index scheduling and per-worker local buffers before final merge, reducing mutex contention under multi-source sync loads.
- Lookup source entries now share source-label storage across file lines, and lookup matching deduplicates by source/target indices before allocating output strings.
- Remote `.iplist` cache loads now keep only parsed network vectors in memory (instead of retaining full cached text alongside parsed CIDRs).
- Added reproducible local performance tooling: Criterion benchmarks for core hot paths (`cargo bench --bench core_perf` via `scripts/perf/run-benchmarks.sh`), a deterministic lookup RSS/time probe (`scripts/perf/measure-lookup-rss.sh`), and a local regression gate script (`scripts/perf/check-regressions.sh`) that fails when slowdown/RSS/time thresholds are exceeded.

### Fixed

- `scripts/install.sh --init` now recovers from the known `kidobo init` failure mode where `systemctl reset-failed kidobo-sync.service` exits with `Unit ... not loaded`, and continues by enabling `kidobo-sync.timer`.

## [0.4.0] - 2026-02-17

### Added

- `kidobo sync` now rewrites the local blocklist file before each run by collapsing/deduplicating entries, sorting IPv4 before IPv6, trimming whitespace, and preserving any header comments so the on-disk list is the minimal canonical representation of the same IP set.
- Added interactive `kidobo ban` / `kidobo unban` commands to manage the local blocklist file (with `--yes` to auto-remove partial matches) so operators can modify the list without editing files manually.

## [0.3.0] - 2026-02-17

### Added

- Added configurable firewall chain action via `ipset.chain_action` with
  allowed values `DROP` (default) and `REJECT` for kidobo chain rules.

### Fixed

- Path resolution no longer hard-fails when the process current directory is
  unavailable unless repo config fallback is explicitly enabled. This allows
  `kidobo init` and other default-path flows to run deterministically.

## [0.2.1] - 2026-02-17

### Changed

- `kidobo lookup` now labels remote matches with the original source URL from
  cache metadata (instead of hashed cache filenames), improving provenance in
  offline lookup output.
- Documentation and maintenance scripts now explicitly use
  `cargo +nightly udeps --all-targets --all-features` for dependency-usage
  checks to match CI behavior.
- Remote conditional-fetch behavior is now shared through a common adapter
  helper, reducing duplicated cache revalidation logic between remote feed and
  GitHub meta loaders.
- `kidobo sync` remote ingestion now keeps parsed CIDRs from cache fetch results
  and avoids reparsing normalized `.iplist` text in worker threads.
- Lookup matching now pre-indexes source CIDR intervals per family, reducing
  repeated overlap scanning work for multi-target lookups.
- Sync/carve normalization now removes redundant collapse/sort/merge passes in
  the core blocklist pipeline while preserving deterministic output ordering.
- Removed the unused `reqwest` `json` feature from dependency configuration.

### Fixed

- Remote feed metadata cache parse/read failures now degrade gracefully to
  metadata-free operation, preserving stale `.iplist` fallback behavior instead
  of hard-failing the source load.
- `kidobo` now exits with code `130` when `SIGINT` is received during command
  execution (after the current command step returns), not only before dispatch.

## [0.2.0] - 2026-02-16

### Changed

- `kidobo init` now runs `systemctl daemon-reload` and
  `systemctl reset-failed kidobo-sync.service` before
  `systemctl enable --now kidobo-sync.timer` when using default system paths
  (the `KIDOBO_ROOT` sandbox flow still skips `systemctl`).
- Added `kidobo flush --cache-only` to clear remote feed cache without
  touching firewall/ipset artifacts.

## [0.1.3] - 2026-02-16

### Changed

- Release automation now resolves release notes from the tag name
  (`release-notes/<tag>.md`) and supports manual reruns for existing tags via
  `workflow_dispatch`.
- `kidobo init` now runs `systemctl daemon-reload` and
  `systemctl enable --now kidobo-sync.timer` automatically when using default
  system paths (the `KIDOBO_ROOT` sandbox flow still skips `systemctl`).

## [0.1.2] - 2026-02-16

### Changed

- Logs are now emitted in a plain `level=<LEVEL> msg=<text>` format without
  ANSI styling or duplicated timestamps, which is easier to read in systemd
  journal output.
- Added configurable remote HTTP request timeout via `remote.timeout_secs`
  (default `30`, range `[1, 3600]`).
- `kidobo init` now prints a deterministic summary of created and unchanged
  paths on successful completion.

### Fixed

- `kidobo sync` now fails early with a clear message when effective IPv4/IPv6
  entries exceed configured `ipset.maxelem`, instead of relying only on a later
  `ipset restore` command failure.
- Command execution now drains `stdout` and `stderr` concurrently while processes
  run, preventing pipe-buffer deadlocks/timeouts on large command output.

## [0.1.1] - 2026-02-16

### Added

- `kidobo init` now creates all operational bootstrap artifacts in one run:
  lock file (`sync.lock`), `kidobo-sync.service`, and `kidobo-sync.timer`.
- `kidobo init` systemd service generation now uses the detected `kidobo`
  executable path and includes `KIDOBO_ROOT` in the unit when set.

### Changed

- GitHub meta safelist source is now configurable via
  `safe.github_meta_url` (default remains `https://api.github.com/meta`).
- `kidobo sync` now uses `safe.github_meta_url` from config instead of a
  hard-coded endpoint.

### Fixed

- Config validation now rejects invalid `safe.github_meta_url` values that do
  not start with `http://` or `https://`.

## [0.1.0] - 2026-02-16

### Added

- Initial public release of `kidobo` CLI.
