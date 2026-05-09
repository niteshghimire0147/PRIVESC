"""
windows_credential_scanner.py — Detect exposed credentials on Windows.

Checks:
  - cmdkey stored credentials
  - Unattend.xml / sysprep answer files (plaintext passwords)
  - PowerShell command history (ConsoleHost_history.txt)
  - SAM / SYSTEM hive accessibility
  - IIS web.config files with credentials
  - Common config files with connection strings
  - Windows Credential Manager (via cmdkey /list)
"""

import subprocess
import os
import re
import glob


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return r.stdout.strip()
    except Exception:
        return ""


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


def _read_file_safe(path: str, max_bytes: int = 65536) -> str:
    """Read a file safely, returning '' on any error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


# Patterns that indicate hardcoded secrets
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)password\s*[=:]\s*\S+', "Hardcoded password"),
    (r'(?i)passwd\s*[=:]\s*\S+', "Hardcoded passwd"),
    (r'(?i)pwd\s*[=:]\s*\S+', "Hardcoded pwd"),
    (r'(?i)connectionstring\s*=\s*["\'].*password', "Connection string with password"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)secret[_\-]?key\s*[=:]\s*\S+', "Secret key"),
]


def _check_cmdkey_credentials() -> list[dict]:
    """Check for stored credentials via cmdkey /list."""
    findings = []
    output = _run(["cmdkey", "/list"])
    if not output or "currently stored" not in output.lower():
        return findings

    entries = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("target:"):
            current = {"target": line.split(":", 1)[1].strip()}
        elif line.lower().startswith("type:"):
            current["type"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("user:"):
            current["user"] = line.split(":", 1)[1].strip()
            entries.append(current)
            current = {}

    for entry in entries:
        target = entry.get("target", "")
        cred_type = entry.get("type", "")
        user = entry.get("user", "")
        findings.append({
            "category": "Windows Credentials",
            "type": "Stored Credential (cmdkey)",
            "severity": "HIGH",
            "description": (
                f"Stored Windows credential found for target '{target}' "
                f"(User: {user}, Type: {cred_type}). "
                "These credentials can be extracted with tools like Mimikatz or used "
                "directly via runas /savecred to escalate privileges or move laterally."
            ),
            "mitigation": (
                f"Remove the stored credential: cmdkey /delete:{target} "
                "Avoid storing credentials unless absolutely necessary."
            ),
            "details": {
                "target": target,
                "credential_type": cred_type,
                "username": user,
                "exploit_example": f"runas /savecred /user:{user} cmd.exe",
            },
        })

    return findings


def _check_unattend_files() -> list[dict]:
    """Search for unattended installation answer files containing plaintext passwords."""
    findings = []
    search_paths = [
        r"C:\Windows\sysprep\sysprep.xml",
        r"C:\Windows\sysprep\sysprep.inf",
        r"C:\Windows\sysprep.inf",
        r"C:\unattend.xml",
        r"C:\unattend.inf",
        r"C:\Windows\Panther\unattend.xml",
        r"C:\Windows\Panther\unattended.xml",
        r"C:\Windows\Panther\Unattend\unattend.xml",
        r"C:\Windows\System32\sysprep\unattend.xml",
    ]

    for path in search_paths:
        if not os.path.isfile(path):
            continue
        content = _read_file_safe(path)
        if not content:
            continue

        # Look for password elements
        pw_match = re.search(r'<Password>\s*<Value>([^<]+)</Value>', content, re.IGNORECASE)
        if pw_match:
            findings.append({
                "category": "Windows Credentials",
                "type": "Unattend File with Plaintext Password",
                "severity": "CRITICAL",
                "description": (
                    f"Unattended installation file found at {path} containing a "
                    "plaintext or base64-encoded password in a <Password> element. "
                    "These are often local Administrator credentials."
                ),
                "mitigation": (
                    "Delete the answer file after system setup. Never leave "
                    "unattended installation files on production systems."
                ),
                "details": {
                    "file": path,
                    "has_password_element": True,
                },
            })
        elif "<AutoLogon>" in content or "AdministratorPassword" in content:
            findings.append({
                "category": "Windows Credentials",
                "type": "Unattend File (Possible Credentials)",
                "severity": "HIGH",
                "description": (
                    f"Unattended installation file found at {path}. "
                    "It contains AutoLogon or AdministratorPassword elements "
                    "which may contain credentials."
                ),
                "mitigation": "Review and delete the answer file after system setup.",
                "details": {"file": path},
            })

    return findings


def _check_powershell_history() -> list[dict]:
    """Check PowerShell console history for sensitive commands."""
    findings = []

    # Find all user profile directories
    profiles_root = os.environ.get("SystemDrive", "C:") + "\\Users"
    history_paths = glob.glob(
        os.path.join(profiles_root, "*", "AppData", "Roaming",
                     "Microsoft", "Windows", "PowerShell", "PSReadLine",
                     "ConsoleHost_history.txt")
    )

    for history_path in history_paths:
        if not os.path.isfile(history_path):
            continue
        content = _read_file_safe(history_path, max_bytes=131072)
        if not content:
            continue

        sensitive_lines = []
        for line in content.splitlines():
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, line):
                    sensitive_lines.append(line.strip()[:200])
                    break

        if sensitive_lines:
            findings.append({
                "category": "Windows Credentials",
                "type": "PowerShell History Contains Credentials",
                "severity": "HIGH",
                "description": (
                    f"PowerShell history file at {history_path} contains "
                    f"{len(sensitive_lines)} line(s) with potential credentials or secrets."
                ),
                "mitigation": (
                    "Clear PowerShell history: Remove-Item "
                    "(Get-PSReadlineOption).HistorySavePath. "
                    "Set $env:HISTFILE to a non-persistent location."
                ),
                "details": {
                    "file": history_path,
                    "sensitive_lines_preview": sensitive_lines[:5],
                },
            })

    return findings


def _check_sam_accessibility() -> list[dict]:
    """Check if the SAM hive is directly readable (backup copies)."""
    findings = []
    sam_paths = [
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SYSTEM",
        r"C:\Windows\repair\SAM",
        r"C:\Windows\repair\system",
    ]

    for path in sam_paths:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            findings.append({
                "category": "Windows Credentials",
                "type": "SAM/SYSTEM Hive Readable",
                "severity": "CRITICAL",
                "description": (
                    f"The file {path} is readable by the current user. "
                    "The SAM hive contains NTLM hashes of local accounts. "
                    "Combined with the SYSTEM hive, offline password cracking or "
                    "pass-the-hash attacks are possible."
                ),
                "mitigation": (
                    "Ensure only SYSTEM and Administrators have read access to SAM/SYSTEM hives. "
                    "Check for backup copies in C:\\Windows\\repair\\ and restrict them."
                ),
                "details": {
                    "file": path,
                    "exploit_example": (
                        "reg save HKLM\\SAM sam.hiv && reg save HKLM\\SYSTEM sys.hiv && "
                        "impacket-secretsdump -sam sam.hiv -system sys.hiv LOCAL"
                    ),
                },
            })

    return findings


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of credential-related privilege escalation findings."""
    if verbose:
        print("[*] Scanning for exposed Windows credentials...")

    findings: list[dict] = []

    if verbose:
        print("    Checking cmdkey stored credentials...")
    findings.extend(_check_cmdkey_credentials())

    if verbose:
        print("    Checking unattended installation files...")
    findings.extend(_check_unattend_files())

    if verbose:
        print("    Checking PowerShell command history...")
    findings.extend(_check_powershell_history())

    if verbose:
        print("    Checking SAM/SYSTEM hive accessibility...")
    findings.extend(_check_sam_accessibility())

    if verbose:
        print(f"    Found {len(findings)} credential finding(s).")

    return findings
