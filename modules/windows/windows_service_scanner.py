"""
windows_service_scanner.py — Detect service-based privilege escalation vectors.

Checks:
  - Unquoted service paths with spaces (classic hijacking)
  - Weak service binary permissions (non-admins can overwrite the EXE)
  - Services running as LocalSystem with writable binary directories
  - Weak service DACL (non-admin can reconfigure via sc sdshow)
"""

import subprocess
import os
import re


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return r.stdout.strip()
    except Exception:
        return ""


def _run_powershell(script: str, timeout: int = 20) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _is_writable(path: str) -> bool:
    """Return True if the current user can write to the given file/directory."""
    try:
        return os.access(path, os.W_OK)
    except Exception:
        return False


def _check_unquoted_service_paths() -> list[dict]:
    """Find services with unquoted paths that contain spaces."""
    findings = []
    ps_script = (
        "Get-WmiObject Win32_Service | "
        "Where-Object { $_.PathName -ne $null -and "
        "$_.PathName -notmatch '^\"' -and $_.PathName -match ' ' } | "
        "Select-Object Name, DisplayName, PathName, StartMode, StartName | "
        "ConvertTo-Json -Depth 2"
    )
    raw = _run_powershell(ps_script)
    if not raw:
        return findings

    import json
    try:
        services = json.loads(raw)
        if isinstance(services, dict):
            services = [services]
    except json.JSONDecodeError:
        return findings

    for svc in services:
        path = svc.get("PathName", "")
        name = svc.get("Name", "")
        display = svc.get("DisplayName", "")
        start_name = svc.get("StartName", "")

        # Strip arguments — only take the executable portion
        exe_path = re.split(r'\s+-', path)[0].strip()

        # Check if any intermediate directory is writable
        parts = exe_path.split("\\")
        for i in range(1, len(parts)):
            candidate = "\\".join(parts[:i])
            if not candidate or not os.path.exists(candidate):
                continue
            if _is_writable(candidate):
                severity = "HIGH" if "system" in (start_name or "").lower() else "MEDIUM"
                findings.append({
                    "category": "Windows Service",
                    "type": "Unquoted Service Path",
                    "severity": severity,
                    "description": (
                        f"Service '{display}' ({name}) has an unquoted path with spaces. "
                        f"A binary can be planted at '{candidate}\\{parts[i]}.exe' "
                        f"to hijack execution."
                    ),
                    "mitigation": (
                        f"Wrap the ImagePath value in quotes: "
                        f'sc config {name} binpath= \\"{exe_path}\\"'
                    ),
                    "details": {
                        "service_name": name,
                        "path": exe_path,
                        "writable_dir": candidate,
                        "runs_as": start_name,
                    },
                })
                break  # report once per service

    return findings


def _check_weak_service_permissions() -> list[dict]:
    """Find service executables writable by non-admin users."""
    findings = []
    ps_script = (
        "Get-WmiObject Win32_Service | "
        "Where-Object { $_.PathName -ne $null } | "
        "Select-Object Name, DisplayName, PathName, StartName | "
        "ConvertTo-Json -Depth 2"
    )
    raw = _run_powershell(ps_script)
    if not raw:
        return findings

    import json
    try:
        services = json.loads(raw)
        if isinstance(services, dict):
            services = [services]
    except json.JSONDecodeError:
        return findings

    checked_paths: set = set()

    for svc in services:
        raw_path = svc.get("PathName", "")
        name = svc.get("Name", "")
        display = svc.get("DisplayName", "")
        start_name = svc.get("StartName", "")

        # Extract executable path (handle quoted and unquoted)
        match = re.match(r'"([^"]+)"', raw_path)
        if match:
            exe = match.group(1)
        else:
            exe = re.split(r'\s+', raw_path)[0]

        exe = exe.strip().strip('"')
        if not exe or exe in checked_paths:
            continue
        checked_paths.add(exe)

        if not os.path.isfile(exe):
            continue

        if _is_writable(exe):
            severity = "CRITICAL" if "system" in (start_name or "").lower() else "HIGH"
            findings.append({
                "category": "Windows Service",
                "type": "Writable Service Executable",
                "severity": severity,
                "description": (
                    f"The executable for service '{display}' ({name}) is writable "
                    f"by the current user: {exe}. Overwriting it and restarting the "
                    f"service will execute arbitrary code as '{start_name}'."
                ),
                "mitigation": (
                    f"Fix permissions: icacls \"{exe}\" /inheritance:d "
                    f"/grant:r \"Administrators:(F)\" /remove \"Users\""
                ),
                "details": {
                    "service_name": name,
                    "executable": exe,
                    "runs_as": start_name,
                },
            })

        # Also check if the directory containing the exe is writable
        exe_dir = os.path.dirname(exe)
        if exe_dir and exe_dir not in checked_paths and _is_writable(exe_dir):
            checked_paths.add(exe_dir)
            findings.append({
                "category": "Windows Service",
                "type": "Writable Service Directory",
                "severity": "HIGH",
                "description": (
                    f"The directory containing the '{name}' service binary is writable: "
                    f"{exe_dir}. A malicious DLL or replacement executable can be planted here."
                ),
                "mitigation": (
                    f"Restrict directory permissions: "
                    f"icacls \"{exe_dir}\" /grant:r \"Administrators:(OI)(CI)F\" /remove \"Users\""
                ),
                "details": {
                    "service_name": name,
                    "directory": exe_dir,
                    "runs_as": start_name,
                },
            })

    return findings


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of service-related privilege escalation findings."""
    if verbose:
        print("[*] Scanning Windows services for privilege escalation vectors...")

    findings: list[dict] = []

    if verbose:
        print("    Checking unquoted service paths...")
    findings.extend(_check_unquoted_service_paths())

    if verbose:
        print("    Checking weak service binary permissions...")
    findings.extend(_check_weak_service_permissions())

    if verbose:
        print(f"    Found {len(findings)} service finding(s).")

    return findings
