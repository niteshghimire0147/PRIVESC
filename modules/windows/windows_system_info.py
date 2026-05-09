"""
windows_system_info.py — Collect Windows system context for the scanner.

Gathers: hostname, OS version, current user, group memberships,
installed hotfixes, architecture, and PowerShell version.
"""

import subprocess
import os
import platform


def _run(cmd: list[str], timeout: int = 10) -> str:
    """Run a subprocess command and return stdout as a string, or '' on error."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _run_powershell(script: str, timeout: int = 15) -> str:
    """Run a PowerShell command and return stdout."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout.strip()
    except Exception:
        return ""


def collect(verbose: bool = False) -> dict:
    """
    Collect Windows system information.

    Returns a dict with keys:
        hostname, os_version, build_number, architecture,
        username, domain, groups, hotfixes, powershell_version,
        path_dirs, is_elevated
    """
    if verbose:
        print("[*] Collecting Windows system information...")

    info: dict = {}

    # Hostname
    info["hostname"] = os.environ.get("COMPUTERNAME", platform.node())

    # OS Version
    os_ver = _run_powershell(
        "(Get-WmiObject Win32_OperatingSystem).Caption + ' ' + "
        "(Get-WmiObject Win32_OperatingSystem).Version"
    )
    info["os_version"] = os_ver if os_ver else platform.version()

    # Build number
    build = _run_powershell("(Get-WmiObject Win32_OperatingSystem).BuildNumber")
    info["build_number"] = build.strip() if build else ""

    # Architecture
    arch = _run_powershell("(Get-WmiObject Win32_OperatingSystem).OSArchitecture")
    info["architecture"] = arch.strip() if arch else platform.machine()

    # Current user
    info["username"] = os.environ.get("USERNAME", _run(["whoami"]))

    # Domain
    info["domain"] = os.environ.get("USERDOMAIN", "")

    # Group memberships via whoami /groups
    groups_raw = _run(["whoami", "/groups"])
    groups = []
    for line in groups_raw.splitlines():
        if "Mandatory Label" in line or "Everyone" in line or "BUILTIN\\" in line or "NT AUTHORITY\\" in line:
            groups.append(line.strip())
    info["groups"] = groups[:20]  # cap for readability

    # Installed hotfixes (last 10)
    hotfixes_raw = _run_powershell(
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 10 HotFixID, InstalledOn | "
        "Format-Table -AutoSize | Out-String"
    )
    info["hotfixes"] = hotfixes_raw if hotfixes_raw else "Unable to retrieve hotfixes"

    # PowerShell version
    ps_ver = _run_powershell("$PSVersionTable.PSVersion.ToString()")
    info["powershell_version"] = ps_ver.strip() if ps_ver else "Unknown"

    # PATH directories
    path_env = os.environ.get("PATH", "")
    info["path_dirs"] = [p.strip() for p in path_env.split(";") if p.strip()]

    # Check if running as elevated (admin)
    elevated_check = _run_powershell(
        "([Security.Principal.WindowsPrincipal]"
        "[Security.Principal.WindowsIdentity]::GetCurrent())"
        ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    info["is_elevated"] = elevated_check.strip().lower() == "true"

    if verbose:
        print(f"    Hostname : {info['hostname']}")
        print(f"    OS       : {info['os_version']}")
        print(f"    User     : {info['username']} ({'Admin' if info['is_elevated'] else 'Non-Admin'})")

    return info
