### Fixed

- `kidobo doctor` and `kidobo init` now only treat `PATH` entries as valid
  binaries when the target is actually executable, preventing false-positive
  preflight success from non-executable stub files.
- `kidobo doctor` now preserves cache-writability failure context in its detail
  output, including whether directory creation, probe-file writes, or probe-file
  cleanup failed.

### Changed

- Large local blocklist rewrite paths now avoid extra retained-line copies,
  reducing peak memory use and improving rewrite speed for large `ban`/`unban`
  and related cleanup operations.
