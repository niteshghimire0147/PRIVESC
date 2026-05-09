"""
compliance_mapper.py — Map findings to security frameworks.

Maps each finding to:
  - MITRE ATT&CK Technique IDs (T1xxx)
  - CIS Benchmark Controls
  - NIST SP 800-53 Controls
  - ISO 27001 Clauses (where applicable)

Usage:
    from analysis.compliance_mapper import enrich_with_compliance
    enriched_findings = enrich_with_compliance(findings)
"""

from typing import Any

# ── Compliance Database ───────────────────────────────────────────────────────
# Each entry: (category_pattern, type_pattern): {framework: [controls]}
# Patterns are matched as substring (case-insensitive) against finding fields.

COMPLIANCE_MAP: list[tuple[tuple[str, str], dict]] = [

    # SUID/SGID / GTFOBins
    (("suid", ""), {
        "mitre_attack": ["T1548.001 — Setuid and Setgid"],
        "cis":          ["CIS Linux 6.1 — Ensure SUID/SGID files are reviewed"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "CM-7 (Least Functionality)"],
        "iso_27001":    ["A.9.4.4 — Use of privileged utility programs"],
    }),

    # File Permissions
    (("permission", ""), {
        "mitre_attack": ["T1222 — File and Directory Permissions Modification",
                         "T1083 — File and Directory Discovery"],
        "cis":          ["CIS Linux 6.1 — Ensure permissions on sensitive files are configured"],
        "nist_800_53":  ["AC-3 (Access Enforcement)", "AC-6 (Least Privilege)"],
        "iso_27001":    ["A.9.4.1 — Information access restriction"],
    }),

    # Cron Jobs
    (("cron", ""), {
        "mitre_attack": ["T1053.003 — Cron", "T1574 — Hijack Execution Flow"],
        "cis":          ["CIS Linux 5.1 — Configure cron"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "CM-6 (Configuration Settings)"],
        "iso_27001":    ["A.9.4.4 — Use of privileged utility programs"],
    }),

    # Kernel CVE
    (("kernel", "cve"), {
        "mitre_attack": ["T1068 — Exploitation for Privilege Escalation"],
        "cis":          ["CIS Linux 1.9 — Ensure updates are applied"],
        "nist_800_53":  ["SI-2 (Flaw Remediation)", "RA-5 (Vulnerability Scanning)"],
        "iso_27001":    ["A.12.6.1 — Management of technical vulnerabilities"],
    }),

    # Linux Capabilities
    (("capabilities", ""), {
        "mitre_attack": ["T1548.001 — Setuid and Setgid"],
        "cis":          ["CIS Linux 6.1 — Ensure capabilities on executables are reviewed"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "CM-7 (Least Functionality)"],
        "iso_27001":    ["A.9.4.4 — Use of privileged utility programs"],
    }),

    # Credentials (all platforms)
    (("credential", ""), {
        "mitre_attack": ["T1552 — Unsecured Credentials",
                         "T1552.001 — Credentials in Files",
                         "T1552.002 — Credentials in Registry"],
        "cis":          ["CIS Linux 6.2 — Shadow passwords", "CIS Windows 16 — Account Policies"],
        "nist_800_53":  ["IA-5 (Authenticator Management)", "SC-28 (Protection of Information at Rest)"],
        "iso_27001":    ["A.9.4.3 — Password management system"],
    }),

    # PATH Hijacking
    (("path", "hijack"), {
        "mitre_attack": ["T1574.007 — Path Interception by PATH Environment Variable"],
        "cis":          ["CIS Linux 6.1 — Review PATH environment variable settings"],
        "nist_800_53":  ["CM-6 (Configuration Settings)", "AC-6 (Least Privilege)"],
        "iso_27001":    ["A.12.6.1 — Management of technical vulnerabilities"],
    }),

    # DLL Hijacking
    (("dll hijack", ""), {
        "mitre_attack": ["T1574.001 — DLL Search Order Hijacking"],
        "cis":          ["CIS Windows 18 — Safe DLL Search Mode"],
        "nist_800_53":  ["CM-6 (Configuration Settings)", "SI-3 (Malicious Code Protection)"],
        "iso_27001":    ["A.12.2.1 — Controls against malware"],
    }),

    # Windows Services
    (("windows service", ""), {
        "mitre_attack": ["T1574.005 — Executable Installer File Permissions Weakness",
                         "T1574.009 — Path Interception by Unquoted Path",
                         "T1543.003 — Windows Service"],
        "cis":          ["CIS Windows 5.x — Windows Services"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "CM-7 (Least Functionality)"],
        "iso_27001":    ["A.12.6.1 — Management of technical vulnerabilities"],
    }),

    # Windows Registry
    (("windows registry", "alwaysinstallelevated"), {
        "mitre_attack": ["T1548.002 — Bypass User Account Control"],
        "cis":          ["CIS Windows 18.9 — Windows Installer policies"],
        "nist_800_53":  ["CM-6 (Configuration Settings)", "AC-6 (Least Privilege)"],
        "iso_27001":    ["A.9.4.4 — Use of privileged utility programs"],
    }),

    # Token Privileges
    (("token privilege", ""), {
        "mitre_attack": ["T1134 — Access Token Manipulation",
                         "T1134.001 — Token Impersonation/Theft"],
        "cis":          ["CIS Windows 2.2 — User Rights Assignment"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "AC-3 (Access Enforcement)"],
        "iso_27001":    ["A.9.2.3 — Management of privileged access rights"],
    }),

    # UAC
    (("uac", ""), {
        "mitre_attack": ["T1548.002 — Bypass User Account Control"],
        "cis":          ["CIS Windows 2.3.17 — UAC Settings"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "CM-6 (Configuration Settings)"],
        "iso_27001":    ["A.9.4.4 — Use of privileged utility programs"],
    }),

    # Scheduled Tasks
    (("scheduled task", ""), {
        "mitre_attack": ["T1053.005 — Scheduled Task",
                         "T1574 — Hijack Execution Flow"],
        "cis":          ["CIS Windows 18.4 — Scheduled Tasks"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "CM-7 (Least Functionality)"],
        "iso_27001":    ["A.9.4.4 — Use of privileged utility programs"],
    }),

    # Windows Kernel CVE
    (("windows kernel", ""), {
        "mitre_attack": ["T1068 — Exploitation for Privilege Escalation"],
        "cis":          ["CIS Windows 18.9 — Windows Update Settings"],
        "nist_800_53":  ["SI-2 (Flaw Remediation)", "RA-5 (Vulnerability Scanning)"],
        "iso_27001":    ["A.12.6.1 — Management of technical vulnerabilities"],
    }),

    # Sudo
    (("service", "sudo"), {
        "mitre_attack": ["T1548.003 — Sudo and Sudo Caching"],
        "cis":          ["CIS Linux 5.3 — Configure sudo"],
        "nist_800_53":  ["AC-6 (Least Privilege)", "AC-3 (Access Enforcement)"],
        "iso_27001":    ["A.9.2.3 — Management of privileged access rights"],
    }),
]


def _match(finding: dict, cat_pattern: str, type_pattern: str) -> bool:
    """Return True if the finding matches the given patterns (substring, case-insensitive)."""
    cat  = finding.get("category", "").lower()
    typ  = finding.get("type", "").lower()
    desc = finding.get("description", "").lower()
    return (
        (not cat_pattern  or cat_pattern  in cat  or cat_pattern  in desc) and
        (not type_pattern or type_pattern in typ  or type_pattern in desc)
    )


def _get_compliance(finding: dict) -> dict:
    """Return the best matching compliance controls for a finding."""
    for (cat_pattern, type_pattern), controls in COMPLIANCE_MAP:
        if _match(finding, cat_pattern, type_pattern):
            return controls
    # Default fallback
    return {
        "mitre_attack": ["T1068 — Exploitation for Privilege Escalation"],
        "cis":          ["CIS General — Apply principle of least privilege"],
        "nist_800_53":  ["AC-6 (Least Privilege)"],
        "iso_27001":    ["A.9.4 — Use of privileged utility programs"],
    }


def enrich_with_compliance(findings: list[dict]) -> list[dict]:
    """
    Add compliance mappings to each finding in-place.

    Adds a 'compliance' key to each finding dict with sub-keys:
        mitre_attack, cis, nist_800_53, iso_27001
    """
    for finding in findings:
        finding["compliance"] = _get_compliance(finding)
    return findings


def get_compliance_summary(findings: list[dict]) -> dict[str, Any]:
    """
    Build a compliance coverage summary across all findings.

    Returns a dict mapping framework → sorted list of unique controls.
    """
    summary: dict[str, set] = {
        "mitre_attack": set(),
        "cis":          set(),
        "nist_800_53":  set(),
        "iso_27001":    set(),
    }
    for finding in findings:
        compliance = finding.get("compliance") or _get_compliance(finding)
        for framework, controls in compliance.items():
            if framework in summary:
                summary[framework].update(controls)

    return {k: sorted(v) for k, v in summary.items()}
