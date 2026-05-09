# Linux Privilege Escalation Automation Toolkit

> **v2.2.0** | Detection-only | Python 3.8+ | Linux & Windows | Web Dashboard included | `.env` config support

A modular, automated security scanner that audits Linux and Windows systems for privilege escalation vectors, misconfigurations, exposed credentials, and known CVEs. Built for authorised penetration testing, security research, and system hardening.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Feature Overview](#feature-overview)
- [Architecture](#architecture)
- [Scanner Modules](#scanner-modules)
- [Threat Intelligence](#threat-intelligence)
- [Web Dashboard](#web-dashboard)
- [Remote Scanning](#remote-scanning)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Project Structure](#project-structure)
- [Risk Scoring](#risk-scoring)
- [Quick Mode](#quick-mode)
- [Exit Codes](#exit-codes)
- [Legal](#legal)

---

## What It Does

PRIVESC runs scanner modules in sequence, enriches every finding with live threat intelligence, feeds results through a weighted risk-scoring and compliance-mapping engine, and produces structured reports in multiple formats — including a persistent web dashboard with scan history.

```
[STEP 1/8] Collect system info    →  hostname · kernel · user · groups · OS
[STEP 2/8] Run scanners           →  suid · perms · services · cron · kernel
                                      caps · creds · path  (+ Windows modules)
[STEP 3/8] Score findings         →  weighted risk score → CRITICAL / HIGH / MEDIUM / LOW
[STEP 3a/8] Threat intelligence   →  NVD · CISA KEV · EPSS · CVE.org enrichment
[STEP 3b/8] Enrichment pipeline   →  MITRE ATT&CK mapping · CIS Benchmark · compliance
[STEP 3c/8] Attack path engine    →  chained multi-step escalation paths
[STEP 4/8] Generate report        →  text · JSON · HTML · SARIF
```

---

## Feature Overview

| Feature | Description |
|---------|-------------|
| **8 Linux scanner modules** | SUID, permissions, services, cron, kernel CVEs, capabilities, credentials, PATH |
| **9 Windows scanner modules** | Privilege, services, registry, UAC, credentials, PATH, tasks, kernel, system info |
| **Threat Intelligence** | Live enrichment from NVD, CISA KEV, EPSS, and CVE.org (MITRE) |
| **CVE auto-update** | Daily scheduler + manual "Update Now" button; 24h cache with configurable interval |
| **Web Dashboard** | FastAPI + SQLite — scan history, host inventory, charts, CVE table, delete controls |
| **Report export** | Download PDF, HTML, TXT, JSON, or SARIF per scan from the dashboard dropdown |
| **Remote SSH scanning** | Scan remote Linux hosts over SSH without installing anything on the target |
| **4 output formats** | Text (ANSI colour), JSON, self-contained HTML, SARIF 2.1.0 |
| **Differential scans** | Compare two JSON scans — shows new, resolved, and persisting findings |
| **Compliance mapping** | MITRE ATT&CK TTP IDs · CIS Benchmark controls |
| **Attack path engine** | Multi-step privilege escalation chains with confidence scoring |
| **Quick mode** | Skip slow filesystem sweeps for fast triage |
| **Cross-platform** | Full Linux support; Windows graceful degradation with native Windows modules |

---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │                  main.py                    │
                    │              CLI Entry Point                │
                    │  -f text|json|html|sarif|all  -o <file>    │
                    │  --quick  --skip  --verbose  --web          │
                    │  --compare OLD NEW  --update-intel          │
                    └──────────────┬──────────────────────────────┘
                                   │
          ┌────────────────────────▼──────────────────────────────┐
          │                STEP 1 — system_info.py                │
          │    hostname · kernel · user · groups · OS · PATH      │
          └────────────────────────┬──────────────────────────────┘
                                   │  system context
          ┌────────────────────────▼──────────────────────────────┐
          │              STEP 2 — Scanner Modules                 │
          │                                                       │
          │  Linux:  suid · perms · services · cron              │
          │          kernel · caps · creds · path                 │
          │                                                       │
          │  Windows: privilege · services · registry · uac      │
          │           credential · path · tasks · kernel · info  │
          │                                                       │
          │  Remote:  ssh_scanner (agentless, passwordless SSH)  │
          └────────────────────────┬──────────────────────────────┘
                                   │  all_findings[]
          ┌────────────────────────▼──────────────────────────────┐
          │   STEP 3 — analysis/engine.py + enrichment pipeline  │
          │                                                       │
          │  Dedup → Sort → Weighted score → Risk level           │
          │  MITRE ATT&CK mapping · CIS Benchmark controls        │
          │  Attack path engine (chained escalation paths)        │
          └────────────────────────┬──────────────────────────────┘
                                   │
          ┌────────────────────────▼──────────────────────────────┐
          │   STEP 3a — intelligence/threat_intel.py              │
          │                                                       │
          │  ┌──────────────┐  ┌────────────┐  ┌─────────────┐  │
          │  │  NVD API v2  │  │  CISA KEV  │  │    EPSS     │  │
          │  │  CVSS scores │  │  Exploited │  │  Exploit    │  │
          │  │  descriptions│  │  in wild   │  │  probability│  │
          │  └──────────────┘  └────────────┘  └─────────────┘  │
          │  ┌──────────────────────────────────────────────────┐ │
          │  │  CVE.org / MITRE  (CVE JSON 5.0)                │ │
          │  │  CWE IDs · Affected vendors · Reference links   │ │
          │  └──────────────────────────────────────────────────┘ │
          └────────────────────────┬──────────────────────────────┘
                                   │  enriched results
          ┌────────────────────────▼──────────────────────────────┐
          │           STEP 4 — Report Generation                  │
          │                                                       │
          │  Text (ANSI)  │  JSON  │  HTML dashboard  │  SARIF   │
          └───────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────┐
  │   Web Dashboard  (python main.py --web)                       │
  │   FastAPI + SQLite + live HTML UI on http://localhost:8765     │
  │   Scan history · Host inventory · CVE Intel panel             │
  │   Report export (PDF/HTML/TXT) · Charts · Auto-refresh        │
  └────────────────────────────────────────────────────────────────┘
```

---

## Scanner Modules

### Linux Modules

| # | Module | Checks |
|---|--------|--------|
| 2a | **SUID/SGID Binaries** | Executables with SUID/SGID bits; GTFOBins cross-reference with exploit examples |
| 2b | **File Permissions** | World-writable files and dirs; `/etc/shadow`, `/etc/sudoers`, `/etc/passwd` |
| 2c | **Services & Sudo** | Systemd service misconfigs; `sudo -l` NOPASSWD, wildcards, dangerous commands |
| 2d | **Cron Jobs** | Writable cron scripts; root-owned crons; scripts in writable directories |
| 2e | **Kernel CVEs** | Running kernel vs. known CVEs (Dirty Pipe, PwnKit, Baron Samedit, Dirty COW…) |
| 2f | **Capabilities** | `getcap` output; dangerous caps (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`…) |
| 2g | **Credentials** | Shell history, `.env` files, hardcoded config secrets, SSH keys, AWS credentials |
| 2h | **PATH Hijacking** | `.` in `$PATH`; writable PATH dirs; missing PATH dirs; unsafe service file PATHs |

### Windows Modules

| Module | Checks |
|--------|--------|
| **windows_privilege_scanner** | AlwaysInstallElevated, token privileges, SeImpersonate, unquoted service paths |
| **windows_service_scanner** | Writable service binaries, weak service permissions, unquoted paths |
| **windows_registry_scanner** | AutoRun keys, weak ACLs on registry hives, credential keys |
| **windows_uac_scanner** | UAC bypass vectors, consent.exe settings, auto-elevation |
| **windows_credential_scanner** | Credential Manager, DPAPI blobs, cleartext in config files |
| **windows_path_scanner** | Writable directories in `%PATH%`, DLL hijacking opportunities |
| **windows_task_scanner** | Scheduled tasks with writable binaries or weak permissions |
| **windows_kernel_scanner** | Windows version vs. known LPE CVEs (PrintNightmare, HiveNightmare, SMBGhost…) |
| **windows_system_info** | OS version, patches, architecture, environment collection |

---

## Threat Intelligence

The toolkit pulls live CVE data from **4 official sources** and caches results locally with a configurable TTL.

| Source | URL | Data Provided |
|--------|-----|---------------|
| **NVD** (NIST) | `nvd.nist.gov` | CVSS scores, severity, CVE descriptions |
| **CISA KEV** | `cisa.gov/kev` | Known actively-exploited CVEs (highest priority flag) |
| **EPSS** (FIRST) | `first.org/epss` | Probability of exploitation in next 30 days (0–100%) |
| **CVE.org** (MITRE) | `cve.org` | CWE weakness IDs, affected vendors/products, reference links |

### Tracked CVEs

| CVE | Name | Severity |
|-----|------|----------|
| CVE-2022-0847 | Dirty Pipe | CRITICAL |
| CVE-2021-4034 | PwnKit | CRITICAL |
| CVE-2021-3156 | Baron Samedit | CRITICAL |
| CVE-2016-5195 | Dirty COW | HIGH |
| CVE-2021-3493 | Ubuntu OverlayFS | HIGH |
| CVE-2022-2588 | Route of Death | HIGH |
| CVE-2021-34527 | PrintNightmare (Windows) | CRITICAL |
| CVE-2021-36934 | HiveNightmare (Windows) | HIGH |
| CVE-2020-0796 | SMBGhost (Windows) | CRITICAL |
| CVE-2019-1388 | UAC cert dialog (Windows) | HIGH |
| CVE-2022-21882 | Win32k LPE (Windows) | HIGH |
| CVE-2023-21674 | ALPC LPE (Windows) | HIGH |

### Update Commands

```bash
# Manual update from CLI
python main.py --update-intel

# Or use the web dashboard → Intelligence → CVE Intel → Update Now
```

Cache is stored at `data/threat_intel_cache.json`. Default TTL is 24 hours. The scheduler starts automatically when the web dashboard runs.

---

## Web Dashboard

Start the web dashboard instead of a CLI scan:

```bash
python main.py --web
# Opens at http://localhost:8765

# Or run directly with uvicorn for more control
uvicorn web.app:app --host 0.0.0.0 --port 8765
```

Install web dependencies first if not already installed:

```bash
pip install -r requirements-web.txt
```

### Dashboard Pages

| Page | Features |
|------|----------|
| **Dashboard** | Overview KPIs, recent scans, risk distribution chart, intel status bar — loads automatically on open |
| **Scan History** | All past scans with severity breakdown, timestamps, delete button, **📄 Report ▾ dropdown** |
| **Hosts** | Inventory of all scanned hosts, last scan time, risk level, delete button |
| **Intelligence → CVE Intel** | Live CVE table (searchable, sortable by CVSS/EPSS), real-time progress with step counter and ETA, Update Now button, configurable interval |

### Report Export (Dashboard)

Every scan row in the Scan History page has a **📄 Report ▾** dropdown button with five export options:

| Format | Description |
|--------|-------------|
| 📕 **PDF Report** | Professional A4 layout — cover page, KPI summary, colour-coded findings, mitigations |
| 🌐 **HTML Report** | Self-contained single-file dashboard (no internet required) |
| 📝 **TXT Report** | Plain-text report — ideal for logging or emailing |
| 📦 **JSON Export** | Full structured data including threat intel and attack paths |
| 🔬 **SARIF Export** | SARIF 2.1.0 for GitHub Advanced Security / CI pipelines |

Scan data is stored in `data/privesc.db` (SQLite). The database persists between restarts and is created automatically on first launch.

---

## Remote Scanning

Scan a remote Linux host over SSH without installing anything on the target:

```bash
python main.py --remote user@192.168.1.100
python main.py --remote user@host --key ~/.ssh/id_rsa
python main.py --remote user@host -f json -o remote_findings.json
```

The SSH scanner uploads and executes the scanner modules on the remote host, collects output, and generates a local report.

---

## Requirements

- **Python** 3.8 or later
- **OS** Linux (primary) / Windows (full support via Windows modules)
- **Core scan** — stdlib only: no pip install needed
- **Web dashboard** — `fastapi uvicorn[standard] pydantic python-multipart`
- **Remote scanning** — `paramiko` (SSH)

> Some checks require elevated privileges (e.g. reading `/etc/shadow`, running `getcap`).  
> Run as root or with `sudo` for complete results. Non-root scans gracefully skip inaccessible paths.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/niteshghimire/linux-privesc-toolkit
cd "Linux Privilege Escalation Automation Toolkit"

# Core scan — no dependencies needed
python main.py --help

# Web dashboard dependencies
pip install -r requirements-web.txt

# Remote scanning
pip install paramiko

# Set up environment config (optional but recommended)
cp .env.example .env
# Then edit .env — add NVD_API_KEY for faster CVE updates
```

---

## Configuration

All configuration is done through a `.env` file in the project root (never committed to git).

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | _(empty)_ | NVD API key — 50 req/30s vs 5 req/30s without key. Get one free at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |
| `WEB_HOST` | `0.0.0.0` | Web server bind address |
| `WEB_PORT` | `8765` | Web server listen port |
| `WEB_DEBUG` | `false` | Enable uvicorn `--reload` (dev only) |

The `.env` file is loaded automatically when the web dashboard starts. No third-party library required — the loader is built into `web/app.py`.

---

## Usage

### Quick-start examples

```bash
# Full local scan — print text report to terminal
python main.py

# Full scan with progress messages
python main.py -v

# Save plain-text report to file
python main.py -o report.txt

# HTML report (great for presentations and demos)
python main.py -f html -o report.html

# Generate all formats at once (adds .txt / .json / .html extensions)
python main.py -f all -o findings -v

# SARIF 2.1.0 output (for CI/CD, GitHub Advanced Security, VS Code)
python main.py -f sarif -o findings.sarif

# Quick scan — skip slow filesystem sweeps
python main.py --quick -f html -o quick.html

# JSON output (pipe into jq, SIEM, or other tools)
python main.py -f json -o findings.json

# Skip specific modules
python main.py --skip kernel,caps

# Disable ANSI colour (for logging or piping)
python main.py --no-color | tee scan.log

# Compare two scans (differential mode)
python main.py --compare old.json new.json

# Update threat intel cache manually
python main.py --update-intel

# Launch web dashboard
python main.py --web

# Launch web dashboard on custom host/port
python main.py --web --host 0.0.0.0 --port 8765
```

### All CLI options

```
python main.py [options]

  -o, --output FILE         Write report to FILE.
                            With -f all, extensions are appended automatically.

  -f, --format FORMAT       Output format (default: text):
                              text    Plain text to stdout / file
                              json    Structured JSON
                              html    Self-contained HTML dashboard
                              sarif   SARIF 2.1.0 (CI/CD integration)
                              all     All four formats

  -v, --verbose             Print per-module progress and timing

  --quick                   Quick mode: skip slow filesystem sweeps

  --no-color                Disable ANSI colour codes

  --skip MODULES            Comma-separated modules to skip:
                              suid, perms, services, cron,
                              kernel, caps, creds, path

  --compare OLD NEW         Differential mode: compare two JSON scan files

  --update-intel            Refresh threat intel cache from all 4 sources

  --no-intel                Skip threat intelligence enrichment

  --no-compliance           Skip MITRE ATT&CK / CIS compliance mapping

  --no-attack-paths         Skip attack path engine

  --web                     Launch the web dashboard (requires FastAPI/uvicorn)

  --host HOST               Web dashboard bind address (default: 127.0.0.1)

  --port PORT               Web dashboard port (default: 8765)

  -h, --help                Show this help message
```

---

## Output Formats

### Text (terminal / file)

ANSI-coloured terminal output with severity-coded findings, executive summary, and per-finding remediation advice. Automatically falls back to plain text when colour is disabled.

### HTML Dashboard

A **fully self-contained single file** — no CDN, no internet required.

- Dark-themed dashboard with severity summary cards
- Expandable finding cards with description, exploit example, and mitigation
- CRITICAL findings auto-expanded on load
- Category breakdown table with per-severity counts
- System info panel with shell user enumeration
- Threat intel enrichment data (CVSS, EPSS, KEV flag, CWE) per finding
- Print-friendly layout

### JSON

Machine-readable structured output including all findings, threat intel enrichment, MITRE ATT&CK mappings, and attack paths. Compatible with jq, SIEM tools, and custom pipelines.

```json
{
  "report_metadata": { "tool": "Linux Privilege Escalation Automation Toolkit", "version": "2.2.0" },
  "system_info": { "hostname": "kali", "kernel_release": "5.15.0-86-generic" },
  "summary": { "critical": 2, "high": 6, "medium": 11, "low": 3, "risk_score": 47, "risk_level": "HIGH" },
  "findings": [
    {
      "category": "SUID/SGID Binary",
      "severity": "HIGH",
      "path": "/usr/bin/find",
      "exploit_example": "find . -exec /bin/sh -p \\; -quit",
      "mitigation": "Remove SUID bit: chmod u-s /usr/bin/find",
      "threat_intel": {
        "cvss_score": null,
        "epss_score": 0.0,
        "exploited_in_wild": false,
        "cwe_ids": [],
        "affected_products": []
      },
      "mitre_attack": { "technique_id": "T1548.001", "technique_name": "Setuid and Setgid" }
    }
  ]
}
```

### SARIF 2.1.0

Standard Static Analysis Results Interchange Format — compatible with GitHub Advanced Security, Azure DevOps, Visual Studio Code, and most modern CI/CD pipelines.

```bash
python main.py -f sarif -o results.sarif
```

### Differential Mode

Compare two JSON scans to see what changed:

```bash
python main.py -f json -o baseline.json   # first scan
# ... make system changes ...
python main.py --compare baseline.json new.json
```

Output highlights: **new findings**, **resolved findings**, and **persisting findings** with severity changes.

---

## Project Structure

```
Linux Privilege Escalation Automation Toolkit/
├── main.py                          # CLI entry point and orchestrator
├── requirements.txt                 # Core optional dependencies
├── requirements-web.txt             # Web dashboard dependencies
├── .env.example                     # Environment variable template (copy to .env)
├── .gitignore                       # Excludes secrets, scan data, generated files
├── README.md                        # This file
├── DISCLAIMER.md                    # Legal and ethical use notice
│
├── modules/                         # Linux scanner modules
│   ├── system_info.py               # OS, kernel, user, group collection
│   ├── suid_scanner.py              # SUID/SGID binary discovery + GTFOBins
│   ├── permission_scanner.py        # World-writable files/dirs, critical perms
│   ├── service_scanner.py           # Systemd misconfigs, sudo rules
│   ├── cron_scanner.py              # Cron job vulnerability checks
│   ├── kernel_scanner.py            # Kernel CVE matching + hardening
│   ├── capabilities_scanner.py      # Linux capabilities via getcap
│   ├── credential_scanner.py        # Secrets, SSH keys, .env files
│   ├── path_scanner.py              # PATH hijacking vectors
│   └── windows/                     # Windows scanner modules
│       ├── windows_privilege_scanner.py
│       ├── windows_service_scanner.py
│       ├── windows_registry_scanner.py
│       ├── windows_uac_scanner.py
│       ├── windows_credential_scanner.py
│       ├── windows_path_scanner.py
│       ├── windows_task_scanner.py
│       ├── windows_kernel_scanner.py
│       └── windows_system_info.py
│
├── analysis/
│   └── engine.py                    # Dedup, sort, weight, aggregate findings
│
├── reporter/
│   ├── generator.py                 # Text and JSON report builders
│   ├── html_generator.py            # Self-contained HTML dashboard
│   └── sarif_generator.py           # SARIF 2.1.0 output
│
├── intelligence/
│   └── threat_intel.py              # NVD · CISA KEV · EPSS · CVE.org feed
│
├── remote/
│   └── ssh_scanner.py               # Agentless SSH remote scanning
│
├── web/
│   ├── app.py                       # FastAPI web application + REST API
│   └── static/
│       └── index.html               # Single-page dashboard UI
│
├── data/
│   ├── gtfobins.json                # Exploitable binaries database
│   ├── kernel_cves.json             # Linux kernel CVE version ranges
│   ├── threat_intel_cache.json      # Cached threat intel (auto-generated)
│   └── privesc.db                   # SQLite scan history (auto-generated)
│
└── tests/
    ├── test_analysis_engine.py      # 12 unit tests for scoring engine
    ├── test_reporter.py             # 9 unit tests for report generation
    └── test_suid_scanner.py         # 6 unit tests for SUID scanner
```

---

## Risk Scoring

Each finding is assigned a severity level. The analysis engine computes a **weighted composite score**:

```
Risk Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)
```

| Severity | Weight | Meaning |
|----------|--------|---------|
| CRITICAL | ×10 | Immediate, directly exploitable path to root |
| HIGH | ×5 | Likely exploitable with minor conditions |
| MEDIUM | ×2 | Exploitable in specific scenarios |
| LOW | ×1 | Informational / hardening recommendation |

**Overall risk level thresholds:**

| Risk Level | Score |
|------------|-------|
| CRITICAL | ≥ 30 |
| HIGH | ≥ 15 |
| MEDIUM | ≥ 5 |
| LOW | < 5 |

Threat intelligence data from EPSS and CISA KEV can **boost** a finding's effective priority score — a finding with a high exploitation probability or active KEV match is surfaced higher regardless of CVSS alone.

---

## Quick Mode

Use `--quick` to reduce scan time on large systems. Quick mode skips the two slowest filesystem-wide `find` sweeps:

| Check | Normal | Quick |
|-------|--------|-------|
| SUID/SGID scan | All of `/` | Common binary dirs only |
| World-writable file sweep | All of `/` | Skipped |
| World-writable directory sweep | All of `/` | Skipped |
| Critical file permissions | ✔ | ✔ |
| Services, sudo, cron, kernel, caps | ✔ | ✔ |
| Credentials, PATH hijacking | ✔ | ✔ |
| Threat intel enrichment | ✔ | ✔ |

Quick mode is ideal for CTF environments, initial triage, or scanning remote hosts over slow connections.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete — overall risk level is LOW |
| `1` | Scan complete — risk level is MEDIUM, HIGH, or CRITICAL |

Useful for scripting and CI:

```bash
python main.py --quick && echo "Low risk" || echo "Issues found — review report"

# CI pipeline example
python main.py -f sarif -o results.sarif
# Upload results.sarif to GitHub Advanced Security / Azure DevOps
```

---

## Tests

```bash
python -m pytest tests/ -v
# 27 tests — analysis engine, reporter, SUID scanner
```

---

## Legal

This tool is for **authorised security testing and educational use only.**

Scanning systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.

Read [DISCLAIMER.md](DISCLAIMER.md) before use.
