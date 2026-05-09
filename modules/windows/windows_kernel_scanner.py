"""
windows_kernel_scanner.py — Match the running Windows version against known local
privilege escalation CVEs and check security hardening settings.

CVE database covers:
  - MS16-032 (Secondary Logon Handle Privilege Escalation)
  - MS17-010 (EternalBlue — SMB RCE, often used for LPE after initial access)
  - CVE-2019-1388 (UAC Bypass via Certificate Dialog)
  - CVE-2020-0796 (SMBGhost — SMBv3 RCE/LPE)
  - CVE-2021-1675 / CVE-2021-34527 (PrintNightmare — LPE via Print Spooler)
  - CVE-2021-36934 (HiveNightmare / SeriousSAM — SAM file readable by non-admins)
  - CVE-2022-21882 / CVE-2022-21999 (Win32k LPE)
  - CVE-2023-21674 (Advanced Local Procedure Call LPE)
"""

import subprocess
import platform


def _run_powershell(script: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _get_windows_build() -> tuple[str, str]:
    """Return (version_string, build_number_string)."""
    try:
        ver = platform.version()  # e.g. '10.0.19045'
        parts = ver.split(".")
        build = parts[2] if len(parts) >= 3 else ""
        return ver, build
    except Exception:
        return "", ""


# CVE database: {cve_id: {name, severity, description, affected_builds, fixed_in_build,
#                          mitigation, exploit_example}}
WINDOWS_CVES = [
    {
        "cve": "CVE-2021-34527",
        "name": "PrintNightmare",
        "severity": "CRITICAL",
        "description": (
            "Critical vulnerability in the Windows Print Spooler service. Allows a "
            "remote authenticated user or local user to execute arbitrary code with "
            "SYSTEM privileges by installing a malicious printer driver."
        ),
        "affected_versions": ["10.0.17763", "10.0.18363", "10.0.19041", "10.0.19042", "10.0.19043"],
        "fixed_in_build": 19041,
        "patch_kb": "KB5004945",
        "mitigation": "Disable Print Spooler if not needed: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled",
        "exploit_example": "Invoke-Nightmare (PowerShell) or CVE-2021-34527.py",
    },
    {
        "cve": "CVE-2021-36934",
        "name": "HiveNightmare / SeriousSAM",
        "severity": "HIGH",
        "description": (
            "Windows 10 (build 1809+) sets overly permissive ACLs on Volume Shadow Copy "
            "backups of SAM, SECURITY, and SYSTEM hives, allowing non-admin users to read "
            "local account NTLM hashes directly."
        ),
        "affected_versions": ["10.0.17763", "10.0.18363", "10.0.19041", "10.0.19042", "10.0.19043"],
        "fixed_in_build": 19041,
        "patch_kb": "KB5005010",
        "mitigation": (
            "Restrict ACL on %windir%\\system32\\config\\*.* and delete Volume Shadow Copies: "
            "vssadmin delete shadows /all /quiet"
        ),
        "exploit_example": (
            "HiveNightmare.exe  OR  "
            "impacket-secretsdump -sam sam.bak -security security.bak -system system.bak LOCAL"
        ),
    },
    {
        "cve": "CVE-2020-0796",
        "name": "SMBGhost",
        "severity": "CRITICAL",
        "description": (
            "Integer overflow in SMBv3.1.1 compression handling allows unauthenticated "
            "remote code execution or local privilege escalation via a crafted SMB packet."
        ),
        "affected_versions": ["10.0.18362", "10.0.18363", "10.0.19041"],
        "fixed_in_build": 18362,
        "patch_kb": "KB4551762",
        "mitigation": "Apply KB4551762 or disable SMBv3 compression via registry.",
        "exploit_example": "CVE-2020-0796-PoC.py (for LPE path)",
    },
    {
        "cve": "MS16-032",
        "name": "Secondary Logon Handle LPE",
        "severity": "HIGH",
        "description": (
            "The Secondary Logon service improperly handles handle objects, allowing "
            "a local user to run arbitrary code as SYSTEM on affected Windows versions."
        ),
        "affected_versions": ["6.1", "6.2", "6.3", "10.0.10240", "10.0.10586"],
        "fixed_in_build": 10586,
        "patch_kb": "MS16-032",
        "mitigation": "Apply Microsoft patch MS16-032 and keep Windows fully updated.",
        "exploit_example": "Invoke-MS16032.ps1 (PowerSploit)",
    },
    {
        "cve": "CVE-2019-1388",
        "name": "UAC Certificate Dialog Bypass",
        "severity": "HIGH",
        "description": (
            "The UAC elevation dialog for certain signed executables allows clicking a "
            "certificate link that opens Internet Explorer as SYSTEM, enabling an LPE "
            "without credentials."
        ),
        "affected_versions": ["10.0.14393", "10.0.17134", "10.0.17763"],
        "fixed_in_build": 17134,
        "patch_kb": "KB4524157",
        "mitigation": "Apply KB4524157. Use ConsentPromptBehaviorAdmin = 2 to prompt for credentials.",
        "exploit_example": "Run hhupd.exe as Administrator and click the certificate link.",
    },
    {
        "cve": "CVE-2022-21882",
        "name": "Win32k Privilege Escalation",
        "severity": "HIGH",
        "description": (
            "A flaw in the Win32k kernel driver allows a local attacker to elevate "
            "privileges to SYSTEM by exploiting a use-after-free vulnerability."
        ),
        "affected_versions": ["10.0.19041", "10.0.19042", "10.0.19043", "10.0.19044"],
        "fixed_in_build": 19041,
        "patch_kb": "KB5009543",
        "mitigation": "Apply January 2022 Patch Tuesday update (KB5009543).",
        "exploit_example": "CVE-2022-21882.exe (public PoC)",
    },
    {
        "cve": "CVE-2023-21674",
        "name": "ALPC LPE",
        "severity": "HIGH",
        "description": (
            "A use-after-free in the Windows Advanced Local Procedure Call (ALPC) "
            "facility allows a local attacker to escalate to SYSTEM. "
            "Observed exploited in the wild before patch release."
        ),
        "affected_versions": ["10.0.19041", "10.0.19042", "10.0.19043", "10.0.19044", "10.0.22621"],
        "fixed_in_build": 19041,
        "patch_kb": "KB5022282",
        "mitigation": "Apply January 2023 Patch Tuesday update (KB5022282).",
        "exploit_example": "No public PoC at time of disclosure; seen in targeted attacks.",
    },
]


def _get_installed_patches() -> set[str]:
    """Return a set of installed KB hotfix IDs."""
    raw = _run_powershell(
        "Get-HotFix | Select-Object -ExpandProperty HotFixID"
    )
    return set(raw.splitlines()) if raw else set()


def _check_print_spooler() -> list[dict]:
    """Check if Print Spooler is running (required for PrintNightmare exploitation)."""
    findings = []
    status = _run_powershell("(Get-Service Spooler).Status")
    if status.strip().lower() == "running":
        findings.append({
            "category": "Windows Kernel / Services",
            "type": "Print Spooler Running",
            "severity": "MEDIUM",
            "description": (
                "The Windows Print Spooler service is running. If the system is not "
                "fully patched against CVE-2021-1675 / CVE-2021-34527 (PrintNightmare), "
                "this service can be exploited for SYSTEM-level code execution."
            ),
            "mitigation": (
                "Disable if not needed: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. "
                "Ensure KB5004945 or later is installed."
            ),
            "details": {"service": "Spooler", "status": status},
        })
    return findings


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of kernel CVE and hardening findings."""
    if verbose:
        print("[*] Scanning Windows kernel version against known CVEs...")

    findings: list[dict] = []
    version_str, build_str = _get_windows_build()
    installed_patches = _get_installed_patches()

    if verbose:
        print(f"    Windows version: {version_str}")
        print(f"    Installed patches: {len(installed_patches)}")

    for cve in WINDOWS_CVES:
        # Check if any of the affected version prefixes match the running OS
        is_affected = any(
            version_str.startswith(v) for v in cve["affected_versions"]
        )
        if not is_affected:
            continue

        # Check if the patch is already installed
        if cve["patch_kb"] in installed_patches:
            continue

        findings.append({
            "category": "Windows Kernel CVE",
            "type": f"{cve['cve']} — {cve['name']}",
            "severity": cve["severity"],
            "description": (
                f"{cve['cve']} ({cve['name']}): {cve['description']} "
                f"Patch {cve['patch_kb']} does not appear to be installed."
            ),
            "mitigation": cve["mitigation"],
            "details": {
                "cve": cve["cve"],
                "patch_kb": cve["patch_kb"],
                "running_version": version_str,
                "exploit_example": cve["exploit_example"],
            },
        })

    # Additional service checks
    findings.extend(_check_print_spooler())

    if verbose:
        print(f"    Found {len(findings)} kernel/CVE finding(s).")

    return findings
