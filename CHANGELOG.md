# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-04-15

### Added
- `setup.py` and `pyproject.toml` for pip-installable packaging
- `Dockerfile` for containerized scanning
- GitHub Actions CI/CD workflows (test + Docker publish)
- Unit tests for analysis engine, SUID scanner, and HTML reporter
- HTML report: inline SVG severity bar chart
- HTML report: `@media print` CSS for PDF export via browser
- HTML report: remediation checklist section
- `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE`

### Changed
- Report footer now includes scan metadata (hostname, kernel, scan duration)

## [2.0.0] - 2025-03-01

### Added
- `capabilities_scanner.py` — Linux capabilities detection via `getcap`
- `credential_scanner.py` — Shell history, `.env`, SSH keys, AWS credentials
- `path_scanner.py` — PATH hijacking: dot-in-PATH, writable dirs, missing dirs
- HTML report generator with dark-theme dashboard
- JSON report format
- Risk scoring engine in `analysis/engine.py`
- GTFOBins database (`data/gtfobins.json`, 36 binaries)
- Kernel CVE database (`data/kernel_cves.json`, 10+ CVEs)

### Changed
- Rewrote all modules to return structured `list[dict]` findings
- Added `--quick` mode that limits filesystem sweep scope
- Added `--skip MODULES` to exclude specific checks

## [1.0.0] - 2024-12-01

### Added
- Initial release
- SUID/SGID scanner with GTFOBins lookup
- File permission scanner
- Service and sudo rule checker
- Cron job scanner
- Kernel CVE matcher
- Text report output
