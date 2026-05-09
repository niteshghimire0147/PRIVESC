"""
windows_privilege_scanner.py — Detect abusable token privileges.

Checks whoami /priv output for dangerous privilege assignments:
  - SeImpersonatePrivilege  → Juicy/Rogue Potato, PrintSpoofer
  - SeAssignPrimaryToken    → Token impersonation
  - SeDebugPrivilege        → Inject into SYSTEM processes (e.g., lsass)
  - SeBackupPrivilege       → Read any file (SAM, NTDS.dit)
  - SeRestorePrivilege      → Write any file
  - SeLoadDriverPrivilege   → Load malicious kernel driver
  - SeTakeOwnershipPrivilege→ Take ownership of protected files/registry
  - SeCreateTokenPrivilege  → Craft arbitrary access tokens
  - SeManageVolumePrivilege → Write to volumes directly
"""

import subprocess


# Map privilege name → (severity, description, exploit_hint)
DANGEROUS_PRIVS: dict[str, tuple[str, str, str]] = {
    "SeImpersonatePrivilege": (
        "HIGH",
        "Allows impersonation of any user token. Exploitable via Juicy Potato, "
        "Rogue Potato, or PrintSpoofer to escalate to SYSTEM.",
        "PrintSpoofer64.exe -i -c powershell.exe  OR  JuicyPotatoNG.exe -t * -p cmd.exe",
    ),
    "SeAssignPrimaryTokenPrivilege": (
        "HIGH",
        "Allows replacing a process's primary access token. Often combined with "
        "SeImpersonatePrivilege for full token impersonation chains.",
        "Use with token duplication tools; see Rogue Potato / TokenMagician.",
    ),
    "SeDebugPrivilege": (
        "CRITICAL",
        "Allows opening any process (including SYSTEM processes) for read/write. "
        "Can be used to dump lsass credentials or inject shellcode into SYSTEM processes.",
        "procdump.exe -ma lsass.exe lsass.dmp  OR inject shellcode into winlogon/lsass",
    ),
    "SeBackupPrivilege": (
        "HIGH",
        "Allows reading any file regardless of ACLs (backup bypass). "
        "Can be used to extract SAM, SYSTEM, and NTDS.dit hive files for offline cracking.",
        'reg save HKLM\\SAM sam.hiv && reg save HKLM\\SYSTEM sys.hiv',
    ),
    "SeRestorePrivilege": (
        "HIGH",
        "Allows writing any file regardless of ACLs (restore bypass). "
        "Can overwrite system binaries or add a backdoor DLL.",
        "Use robocopy /B or custom tool to write to protected paths.",
    ),
    "SeLoadDriverPrivilege": (
        "CRITICAL",
        "Allows loading arbitrary kernel drivers. A malicious signed (or test-mode) "
        "driver can disable security controls or escalate privileges at kernel level.",
        "EOPLOADDRIVER + vulnerable driver (e.g., Capcom.sys) for kernel code execution.",
    ),
    "SeTakeOwnershipPrivilege": (
        "HIGH",
        "Allows taking ownership of any securable object (file, registry key, service). "
        "Can be combined with SeRestorePrivilege to overwrite protected resources.",
        "takeown /F C:\\Windows\\System32\\cmd.exe && icacls cmd.exe /grant Everyone:F",
    ),
    "SeCreateTokenPrivilege": (
        "CRITICAL",
        "Allows creating arbitrary access tokens with any SID, including local Administrator. "
        "Effectively grants full control over the system.",
        "Use custom NtCreateToken exploit to forge a SYSTEM token.",
    ),
    "SeManageVolumePrivilege": (
        "MEDIUM",
        "Allows direct low-level writes to volumes, bypassing filesystem ACLs. "
        "Can be used to overwrite protected system files at the raw disk level.",
        "Use custom tool or exploit for raw volume writes to plant backdoor.",
    ),
    "SeCreateSymbolicLinkPrivilege": (
        "MEDIUM",
        "Allows creating symbolic links, which can be used in link-following attacks "
        "to redirect file operations of privileged processes.",
        "Create a symlink to redirect a privileged write to an arbitrary location.",
    ),
}


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return r.stdout.strip()
    except Exception:
        return ""


def _parse_whoami_priv(raw: str) -> dict[str, str]:
    """
    Parse 'whoami /priv' output into {privilege_name: state}.
    State is either 'Enabled' or 'Disabled'.
    """
    privs: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("Se"):
            state = parts[-1]  # last token is Enabled/Disabled
            privs[parts[0]] = state
    return privs


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of dangerous token privilege findings."""
    if verbose:
        print("[*] Scanning token privileges (whoami /priv)...")

    findings: list[dict] = []

    raw = _run(["whoami", "/priv"])
    if not raw:
        if verbose:
            print("    Unable to run whoami /priv.")
        return findings

    assigned_privs = _parse_whoami_priv(raw)

    for priv_name, state in assigned_privs.items():
        if priv_name in DANGEROUS_PRIVS:
            severity, description, exploit = DANGEROUS_PRIVS[priv_name]
            # Enabled privileges are more immediately dangerous
            if state.lower() == "enabled":
                actual_severity = severity  # as defined
            else:
                # Disabled but assigned — can often be enabled programmatically
                actual_severity = "MEDIUM" if severity == "CRITICAL" else "LOW"

            findings.append({
                "category": "Windows Token Privileges",
                "type": f"Dangerous Privilege: {priv_name}",
                "severity": actual_severity,
                "description": (
                    f"{priv_name} is {state}. {description}"
                ),
                "mitigation": (
                    f"Remove {priv_name} from this account if not required. "
                    "Use the principle of least privilege — assign only necessary rights "
                    "via Local Security Policy → User Rights Assignment."
                ),
                "details": {
                    "privilege": priv_name,
                    "state": state,
                    "exploit_example": exploit,
                },
            })

    if verbose:
        print(f"    Assigned privileges: {len(assigned_privs)}, dangerous: {len(findings)}")

    return findings
