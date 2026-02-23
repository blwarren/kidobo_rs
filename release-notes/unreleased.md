### Changed

- `kidobo sync` now supports `--timer`, which emits per-stage timing logs (`stage_ms` and cumulative `total_ms`) across path/config/lock setup and major sync pipeline phases.
- Changelog maintenance now uses `release-notes/unreleased.md` as the manual edit target and generates `CHANGELOG.md` via `./scripts/changelog/generate.sh`, with pre-commit and CI checks enforcing up-to-date generated output.
