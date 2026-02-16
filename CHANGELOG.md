# Changelog

All notable changes to this project should be documented in this file.

The format is based on Keep a Changelog, with one section per release.

## [Unreleased]

### Changed

- Logs are now emitted in a plain `level=<LEVEL> msg=<text>` format without
  ANSI styling or duplicated timestamps, which is easier to read in systemd
  journal output.

### Fixed

- `kidobo sync` now fails early with a clear message when effective IPv4/IPv6
  entries exceed configured `ipset.maxelem`, instead of relying only on a later
  `ipset restore` command failure.

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
