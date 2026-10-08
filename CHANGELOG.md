# Changelog

This project follows semantic versioning.

## Unreleased

### Added

- Command/subcommand CLI for passive recon, authorized TCP scans, router audits, file analysis, local inventory, report rendering, and effective-settings display.
- Optional TOML configuration with validated command-line overrides, target/port/path validation, and configurable logging levels.
- Shared network-assessment orchestration so the interactive menu and command mode call the same feature functions.
- Evidence-based private-router service assessments with structured findings, cautious TLS and HTTP observations, and normalized NVD advisory candidates.
- Provenance-preserving passive intelligence records, evidence-backed relationships, normalized NVD CVE data, and conservative product/version correlation through `intel` and `cve` commands.
- Structured local artifact analysis with signature-aware identification, streaming identification hashes, bounded PDF/DOCX extraction, normalized indicators, metadata evidence, conservative findings, and JSON/CSV/text reporting through `file`.
- Deterministic risk assessment of saved report findings through `assess`, preserving source evidence and provenance while adding confidence-aware scores, priorities, aggregation, and JSON/CSV/text summaries.
- Historical baseline capture and comparison through `baseline save` and `compare`, enabling deterministic detection of new, changed, resolved, and not-observed findings without mutating the source reports.

### Changed

- Kept the interactive menu as the default when SENTINEL starts without a command, while retaining the prior option-style commands.
- Reports can be written beneath the configured report directory, including automatically named reports when an output directory is selected.

## 0.2.0 - 2026-10-07

### Added

- Installable `sentinel` Python package with `python -m sentinel` and `sentinel` command entry points.
- Compatibility launchers for the prior SENTINEL script name and legacy `ip finder.py` name.
- Shared default configuration and an isolated TCP scanner module.

### Changed

- Organized existing recon, network, router, document extraction, and report features into package modules.
- Converted internal imports to package-relative imports.
- Preserved the existing CLI and authorized-scope behavior during the package migration.
