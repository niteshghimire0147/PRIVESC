# Linux Privilege Escalation Automation Toolkit

> **Detection-only** | Python 3.6+ | No external dependencies | Linux compatibility mode

A modular automated security scanner that audits Linux systems for common privilege escalation vectors, misconfigurations, and exposed credentials. Built for authorised penetration testing, security coursework, and system hardening.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Architecture](#architecture)
- [Scanner Modules](#scanner-modules)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Project Structure](#project-structure)
- [Risk Scoring](#risk-scoring)
- [Quick Mode](#quick-mode)
- [Data Files](#data-files)
- [Exit Codes](#exit-codes)
- [Legal](#legal)

---

## What It Does

PRIVESC runs eight scanner modules in sequence, feeds every finding into a weighted risk-scoring engine, and produces a structured report in your choice of format. It mirrors real-world tools like LinPEAS and LinEnum but is written as clean, readable Python so you can understand, extend, and present every check it performs.

```
[STEP 1/8] Collect system info  →  hostname, kernel, user, groups, shell users
[STEP 2/8] Run scanners         →  suid · perms · services · cron ·
                                    kernel · caps · credentials · path
[STEP 3/8] Score findings       →  weighted risk score → CRITICAL / HIGH / MEDIUM / LOW
[STEP 4/8] Generate report      →  text · JSON · HTML
```

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │               main.py                   │
                    │           CLI Entry Point               │
                    │  -f text|json|html|all  -o <file>       │
                    │  --quick  --skip  --verbose             │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │         STEP 1 — system_info.py         │
                    │  hostname · kernel · user · groups      │
                    │  shell users · sudo version · PATH      │
                    └──────────────────┬──────────────────────┘
                                       │  system context
          ┌────────────────────────────▼────────────────────────────┐
          │                STEP 2 — Scanner Modules                 │
          │                                                         │
          │  ┌─────────────────────┐   ┌─────────────────────────┐  │
          │  │   suid_scanner      │   │   permission_scanner    │  │
          │  │  SUID/SGID Binaries │   │  World-Writable Files   │  │
          │  │  + GTFOBins lookup ◄├───┤  Critical File Perms    │  │
          │  └─────────────────────┘   └─────────────────────────┘  │
          │                                                         │
          │  ┌─────────────────────┐   ┌─────────────────────────┐  │
          │  │  service_scanner    │   │    cron_scanner         │  │
          │  │  Systemd Services   │   │  Cron Job Scripts       │  │
          │  │  Sudo Rules/NOPASSWD│   │  Writable Cron Paths    │  │
          │  └─────────────────────┘   └─────────────────────────┘  │
          │                                                         │
          │  ┌─────────────────────┐   ┌─────────────────────────┐  │
          │  │  kernel_scanner     │   │  capabilities_scanner   │  │
          │  │  CVE Version Match ◄├───┤  getcap Output          │  │
          │  │  Hardening Checks   │   │  Dangerous cap_* Flags  │  │
          │  └─────────────────────┘   └─────────────────────────┘  │
          │                                                         │
          │  ┌─────────────────────┐   ┌─────────────────────────┐  │
          │  │ credential_scanner  │   │    path_scanner         │  │
          │  │  Shell History      │   │  Dot/Empty in $PATH     │  │
          │  │  .env / SSH Keys    │   │  Writable PATH Dirs     │  │
          │  │  AWS / API Secrets  │   │  sudo env_reset Check   │  │
          │  └─────────────────────┘   └─────────────────────────┘  │
          │                                                         │
          └───────────────────────┬─────────────────────────────────┘
                                  │  all_findings[]
          ┌───────────────────────▼─────────────────────────────────┐
          │              data/ — Reference Databases                 │
          │                                                         │
          │   gtfobins.json                kernel_cves.json         │
          │   ─────────────                ───────────────          │
          │   36 exploitable binaries      CVE-2022-0847 Dirty Pipe │
          │   with exploit commands        CVE-2021-4034 PwnKit     │
          │   used by suid_scanner &       CVE-2021-3156 Baron Sam  │
          │   capabilities_scanner         CVE-2016-5195 Dirty COW  │
          │                                + more                   │
          └───────────────────────┬─────────────────────────────────┘
                                  │
          ┌───────────────────────▼─────────────────────────────────┐
          │             STEP 3 — analysis/engine.py                 │
          │                                                         │
          │   Deduplicate  →  Sort by severity  →  Weighted score   │
          │   CRITICAL×10  +  HIGH×5  +  MEDIUM×2  +  LOW×1        │
          │   score ≥ 30 → CRITICAL  |  ≥ 15 → HIGH                │
          │   score ≥  5 → MEDIUM    |  <  5 → LOW                 │
          └───────────────────────┬─────────────────────────────────┘
                                  │  results{ summary, findings }
          ┌───────────────────────▼─────────────────────────────────┐
          │             STEP 4 — Report Generation                  │
          │                                                         │
          │  ┌───────────────┐  ┌──────────────┐  ┌─────────────┐  │
          │  │  Text Report  │  │ JSON Report  │  │ HTML Report │  │
          │  │  ───────────  │  │ ──────────── │  │ ─────────── │  │
          │  │  Terminal +   │  │  Structured  │  │  Dark-theme │  │
          │  │  plain file   │  │  machine-    │  │  dashboard  │  │
          │  │  ANSI colour  │  │  readable    │  │  self-      │  │
          │  │  output       │  │  output      │  │  contained  │  │
          │  └───────────────┘  └──────────────┘  └─────────────┘  │
          └─────────────────────────────────────────────────────────┘
```

---

## Scanner Modules

| # | Module | Checks |
|---|--------|--------|
| 2a | **SUID/SGID Binaries** | Executables with SUID/SGID bits; GTFOBins cross-reference |
| 2b | **File Permissions** | World-writable files and dirs; `/etc/shadow`, `/etc/sudoers`, `/etc/passwd` |
| 2c | **Services & Sudo** | Systemd service misconfigs; `sudo -l` NOPASSWD, wildcards, dangerous commands |
| 2d | **Cron Jobs** | Writable cron scripts; root-owned crons; scripts in writable directories |
| 2e | **Kernel CVEs** | Running kernel vs. known CVEs (Dirty Pipe, PwnKit, Baron Samedit, Dirty COW…) |
| 2f | **Capabilities** | `getcap` output; dangerous caps (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`…) |
| 2g | **Credentials** | Shell history, `.env` files, hardcoded config secrets, SSH keys, AWS credentials |
| 2h | **PATH Hijacking** | `.` in `$PATH`; writable PATH dirs; missing PATH dirs; unsafe service file PATHs |

---

## Requirements

- **Python** 3.6 or later
- **OS** Linux (Primary) / Windows (Graceful degradation)
- **Dependencies** None — standard library only (`subprocess`, `os`, `stat`, `re`, `json`, `glob`, `argparse`, `datetime`)

> Some checks require elevated privileges (e.g. reading `/etc/shadow`, running `getcap`).  
> Run as root or with `sudo` for complete results. Non-root or Windows scans gracefully skip inaccessible paths and missing system commands.

### 🪟 Windows Compatibility (Recent Updates)
While primarily built for Linux target auditing, the toolkit now safely executes on Windows without crashing due to cross-platform parsing features:
- **Cross-Platform File I/O:** Strict UTF-8 enforcement with a safe fallback (`errors='replace'`) resolves `UnicodeDecodeError` exceptions across varied OS environments/languages.
- **Terminal & Output:** Auto-reconfiguration of `sys.stdout` to UTF-8 enables ANSI text colors and terminal layouts to correctly load within Windows CMD/PowerShell. 
- **Subprocess Safety:** Unrecognized system binaries trigger handled exceptions rather than halting script execution, allowing full scan generation regardless of the underlying OS structure.

---

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd linux-tool

# No pip install required — run directly
python3 main.py --help
```

---

## Usage

### Quick-start examples

```bash
# Full scan — print text report to terminal
python3 main.py

# Full scan with progress messages
python3 main.py -v

# Save plain-text report to file
python3 main.py -o report.txt

# HTML report (great for presentations and demos)
python3 main.py -f html -o report.html

# Generate all three formats at once
python3 main.py -f all -o findings -v

# Quick scan + HTML (fast — ideal for CTF or initial triage)
python3 main.py --quick -f html -o quick_report.html

# JSON output only (pipe into jq, SIEM, or other tools)
python3 main.py -f json -o findings.json

# Skip slow modules, keep colour output in terminal
python3 main.py --skip kernel,caps

# Disable colour (for logging or piping)
python3 main.py --no-color | tee scan.log
```

### All options

```
python3 main.py [options]

  -o, --output FILE       Write report to FILE.
                          When using -f all, extensions (.txt / .json / .html)
                          are appended automatically.

  -f, --format FORMAT     Output format:
                            text   Plain text to stdout (default)
                            json   Structured JSON
                            html   Self-contained HTML dashboard
                            all    All three formats

  -v, --verbose           Print per-module progress and timing

  --quick                 Quick mode: skip slow find-based filesystem sweeps
                          (see Quick Mode section below)

  --no-color              Disable ANSI colour codes in terminal output

  --skip MODULES          Comma-separated list of modules to skip:
                            suid, perms, services, cron,
                            kernel, caps, creds, path

  -h, --help              Show this help message
```

---

## Output Formats

### Text (terminal / file)

```
════════════════════════════════════════════════════════════════════════
  LINUX PRIVILEGE ESCALATION SCANNER — SECURITY REPORT
════════════════════════════════════════════════════════════════════════
  Generated : 2025-11-01 14:32:11
  Hostname  : kali
  User      : user  (non-root)
  Kernel    : 5.15.0-86-generic
  OS        : Ubuntu 22.04.3 LTS

─── EXECUTIVE SUMMARY ──────────────────────────────────────────────────
  Overall Risk Level : HIGH
  Risk Score         : 47

  CRITICAL :    2  |  HIGH :    6  |  MEDIUM :   11  |  LOW :    3
  Total Findings     : 22

─── DETAILED FINDINGS ──────────────────────────────────────────────────

  ──────────────────────────────────────────────────────────────────────
  [HIGH]  #001  SUID/SGID Binary → SUID Binary with GTFOBins Exploit
  ──────────────────────────────────────────────────────────────────────
  Path/Target  : /usr/bin/find
  Bit Type     : SUID
  In GTFOBins  : Yes ⚠
  ··································································
  EXPLOIT EXAMPLE (for authorised testing only):
    find . -exec /bin/sh -p \; -quit
  ··································································
  MITIGATION:
    Remove SUID bit if not required: chmod u-s /usr/bin/find
```

### HTML Dashboard

The HTML report is a **fully self-contained single file** — no CDN, no internet required.

- Dark-themed dashboard with severity summary cards
- Expandable finding cards with description, exploit example, and mitigation
- CRITICAL findings auto-expanded on load
- Category breakdown table with per-severity counts
- System info panel with shell user enumeration
- Print-friendly layout via CSS media query

### JSON

```json
{
  "report_metadata": {
    "generated_at": "2025-11-01 14:32:11",
    "tool": "Linux Privilege Escalation Automation Toolkit",
    "version": "1.0.0"
  },
  "system_info": { "hostname": "kali", "kernel_release": "5.15.0-86-generic" },
  "summary": {
    "critical": 2, "high": 6, "medium": 11, "low": 3,
    "total": 22, "risk_score": 47, "risk_level": "HIGH"
  },
  "findings": [
    {
      "category": "SUID/SGID Binary",
      "type": "SUID Binary with GTFOBins Exploit",
      "severity": "HIGH",
      "path": "/usr/bin/find",
      "in_gtfobins": true,
      "exploit_example": "find . -exec /bin/sh -p \\; -quit",
      "mitigation": "Remove SUID bit if not required: chmod u-s /usr/bin/find"
    }
  ]
}
```

---

## Project Structure

```
linux-tool/
├── main.py                       # CLI entry point and orchestrator
├── requirements.txt              # No external dependencies (stdlib only)
├── README.md                     # This file
├── DISCLAIMER.md                 # Legal and ethical use notice
│
├── modules/                      # Scanner modules (Step 2)
│   ├── __init__.py
│   ├── system_info.py            # OS, kernel, user, group info collection
│   ├── suid_scanner.py           # SUID/SGID binary discovery + GTFOBins lookup
│   ├── permission_scanner.py     # World-writable files/dirs, critical file perms
│   ├── service_scanner.py        # Systemd service misconfigs, sudo rules
│   ├── cron_scanner.py           # Cron job vulnerability checks
│   ├── kernel_scanner.py         # Kernel CVE matching + hardening checks
│   ├── capabilities_scanner.py   # Linux capabilities via getcap
│   ├── credential_scanner.py     # Exposed secrets, SSH keys, .env files
│   └── path_scanner.py           # PATH hijacking vectors
│
├── analysis/                     # Scoring engine (Step 3)
│   ├── __init__.py
│   └── engine.py                 # Dedup, sort, weight, and aggregate findings
│
├── reporter/                     # Report generation (Step 4)
│   ├── __init__.py
│   ├── generator.py              # Text and JSON report builders
│   └── html_generator.py         # Self-contained HTML dashboard generator
│
└── data/                         # Reference databases
    ├── gtfobins.json             # Exploitable binaries with exploit examples
    └── kernel_cves.json          # Known CVEs keyed by kernel version range
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

---

## Quick Mode

Use `--quick` to reduce scan time significantly on large systems. Quick mode skips the two slowest filesystem-wide `find` sweeps:

| Check | Normal | Quick |
|-------|--------|-------|
| SUID/SGID scan | All of `/` | `/usr/bin`, `/bin`, `/sbin`, `/usr/local/bin`, `/opt` only |
| World-writable file sweep | All of `/` | Skipped |
| World-writable directory sweep | All of `/` | Skipped |
| Critical file permissions | Yes | Yes |
| Home directory permissions | Yes | Yes |
| Services, sudo, cron, kernel, caps | Yes | Yes |
| Credentials, PATH hijacking | Yes | Yes |

Quick mode is ideal for CTF environments, initial triage, or when running on a remote system over SSH where speed matters.

---

## Data Files

### `data/gtfobins.json`

Curated subset of [GTFOBins](https://gtfobins.github.io/) covering binaries commonly exploitable via SUID bits or Linux capabilities. Each entry includes:
- `exploit` — command to escalate privileges
- `notes` — explanation of why the binary is dangerous

### `data/kernel_cves.json`

Known local privilege escalation CVEs matched against the running kernel version. Includes:

| CVE | Name | Severity |
|-----|------|----------|
| CVE-2022-0847 | Dirty Pipe | CRITICAL |
| CVE-2021-4034 | PwnKit | CRITICAL |
| CVE-2021-3156 | Baron Samedit | CRITICAL |
| CVE-2016-5195 | Dirty COW | HIGH |
| CVE-2021-3493 | Ubuntu OverlayFS | HIGH |
| CVE-2022-2588 | Route of Death | HIGH |
| And more… | | |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete — overall risk level is LOW |
| `1` | Scan complete — risk level is MEDIUM, HIGH, or CRITICAL |

Useful for scripting and CI:

```bash
python3 main.py --quick && echo "System passed low-risk check" || echo "Issues found — review report"
```

---

## Legal

This tool is for **authorised security testing and educational use only.**

Read [DISCLAIMER.md](DISCLAIMER.md) before use.
