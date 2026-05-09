"""
windows_path_scanner.py — Detect PATH hijacking and DLL hijacking vectors on Windows.

Checks:
  - Writable directories in %PATH%
  - Missing directories in %PATH% (phantom directory creation attack)
  - DLL search order hijacking: writable dirs before system dirs
  - Known applications vulnerable to DLL hijacking
"""

import os
import subprocess


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


# System directories that should always come before user-writable dirs
SYSTEM_DIRS = {
    r"C:\Windows\System32",
    r"C:\Windows",
    r"C:\Windows\SysWOW64",
}


def _check_writable_path_dirs() -> list[dict]:
    """Detect directories in %PATH% that the current user can write to."""
    findings = []
    path_env = os.environ.get("PATH", "")
    path_dirs = [d.strip().rstrip("\\") for d in path_env.split(";") if d.strip()]

    system_dir_seen = False
    for directory in path_dirs:
        norm = directory.upper()
        if any(s.upper() in norm for s in SYSTEM_DIRS):
            system_dir_seen = True

        if not os.path.isdir(directory):
            continue

        if os.access(directory, os.W_OK):
            # More dangerous if it appears before system directories
            severity = "HIGH" if not system_dir_seen else "MEDIUM"
            findings.append({
                "category": "Windows PATH Hijacking",
                "type": "Writable Directory in %PATH%",
                "severity": severity,
                "description": (
                    f"The directory '{directory}' in %PATH% is writable by the current user"
                    + (" and appears before system directories" if not system_dir_seen else "")
                    + ". A malicious executable placed here may be loaded instead of a "
                    "legitimate system binary."
                ),
                "mitigation": (
                    f"Remove write permissions from '{directory}' for non-admin users: "
                    f'icacls "{directory}" /remove "Users" /T'
                ),
                "details": {
                    "directory": directory,
                    "before_system_dirs": not system_dir_seen,
                },
            })

    return findings


def _check_missing_path_dirs() -> list[dict]:
    """Detect directories in %PATH% that do not exist (phantom directory attack)."""
    findings = []
    path_env = os.environ.get("PATH", "")
    path_dirs = [d.strip().rstrip("\\") for d in path_env.split(";") if d.strip()]

    for directory in path_dirs:
        if not directory:
            continue
        if not os.path.exists(directory):
            # Check if the parent is writable (can we create the missing dir?)
            parent = os.path.dirname(directory)
            can_create = os.path.isdir(parent) and os.access(parent, os.W_OK)
            if can_create:
                findings.append({
                    "category": "Windows PATH Hijacking",
                    "type": "Missing PATH Directory (Phantom Dir Attack)",
                    "severity": "MEDIUM",
                    "description": (
                        f"The PATH directory '{directory}' does not exist, but its parent "
                        f"'{parent}' is writable. An attacker can create this directory and "
                        "plant malicious executables that will be found before legitimate ones."
                    ),
                    "mitigation": (
                        f"Create the missing directory '{directory}' with correct permissions, "
                        "or remove it from the PATH."
                    ),
                    "details": {
                        "missing_directory": directory,
                        "parent_writable": parent,
                    },
                })

    return findings


def _check_dll_hijacking_opportunities() -> list[dict]:
    """
    Check for DLL search order hijacking: identify writable directories that appear
    before System32 in the DLL search order for running processes.
    """
    findings = []

    # Windows DLL search order (simplified): process dir, System32, Windows, PATH dirs
    # If the process current directory or a writable PATH dir comes first, hijacking is possible

    # Check if current working directory is writable (often the process dir)
    cwd = os.getcwd()
    if os.access(cwd, os.W_OK):
        # Check if it's not a system directory
        if not any(s.lower() in cwd.lower() for s in ["system32", "syswow64", r"c:\windows"]):
            findings.append({
                "category": "Windows PATH Hijacking",
                "type": "Writable Working Directory (DLL Hijacking)",
                "severity": "MEDIUM",
                "description": (
                    f"The current working directory '{cwd}' is writable. "
                    "Windows searches the current directory before System32 for DLLs. "
                    "Planting a malicious DLL here may be loaded by privileged applications "
                    "that execute from this directory."
                ),
                "mitigation": (
                    "Avoid running privileged processes from user-writable directories. "
                    "Use the SafeDllSearchMode registry setting: "
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1"
                ),
                "details": {
                    "working_directory": cwd,
                },
            })

    # Check if SafeDllSearchMode is disabled
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager"
        ) as k:
            val, _ = winreg.QueryValueEx(k, "SafeDllSearchMode")
            if str(val) == "0":
                findings.append({
                    "category": "Windows PATH Hijacking",
                    "type": "SafeDllSearchMode Disabled",
                    "severity": "HIGH",
                    "description": (
                        "SafeDllSearchMode is set to 0 in the registry, meaning Windows "
                        "will search the current working directory before System32 when "
                        "loading DLLs. This greatly increases DLL hijacking risk."
                    ),
                    "mitigation": (
                        r"Set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"
                        r"\SafeDllSearchMode to 1 (or delete the value to use the default of 1)."
                    ),
                    "details": {
                        "registry_value": "SafeDllSearchMode",
                        "current_value": val,
                    },
                })
    except Exception:
        pass

    return findings


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of PATH/DLL hijacking findings."""
    if verbose:
        print("[*] Scanning for Windows PATH and DLL hijacking vectors...")

    findings: list[dict] = []

    if verbose:
        print("    Checking writable PATH directories...")
    findings.extend(_check_writable_path_dirs())

    if verbose:
        print("    Checking missing PATH directories...")
    findings.extend(_check_missing_path_dirs())

    if verbose:
        print("    Checking DLL hijacking opportunities...")
    findings.extend(_check_dll_hijacking_opportunities())

    if verbose:
        print(f"    Found {len(findings)} PATH/DLL finding(s).")

    return findings
