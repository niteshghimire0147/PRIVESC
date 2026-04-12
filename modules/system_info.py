"""
system_info.py — Step 1: Collect system baseline information.

Gathers OS, user, kernel, and environment data to provide context
for all subsequent privilege escalation checks.
"""

import subprocess
import os
import platform


def _run(cmd, shell=True):
    """Run a shell command and return stripped stdout, or empty string on error."""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        return result.stdout.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def collect():
    """
    Collect system information.

    Returns:
        dict: Baseline system information with keys:
            hostname, current_user, user_id, groups, kernel_version,
            kernel_release, os_name, os_version, shell_users, env_path,
            is_root
    """
    info = {}

    # Hostname
    info["hostname"] = _run("hostname") or platform.node()

    # Current user and UID/GID
    info["current_user"] = _run("whoami") or os.environ.get("USER", "unknown")
    id_output = _run("id")
    info["user_id"] = id_output

    # Parse UID numerically for root check
    try:
        uid_part = id_output.split("uid=")[1].split("(")[0]
        info["is_root"] = (uid_part == "0")
    except (IndexError, ValueError):
        info["is_root"] = getattr(os, 'geteuid', lambda: 1)() == 0

    # Group memberships
    groups_raw = _run("groups")
    info["groups"] = groups_raw.split() if groups_raw else []

    # Kernel information
    uname_full = _run("uname -a")
    info["kernel_version"] = uname_full
    info["kernel_release"] = _run("uname -r")
    info["kernel_machine"] = _run("uname -m")

    # OS release
    os_release = {}
    os_release_raw = _run("cat /etc/os-release 2>/dev/null")
    for line in os_release_raw.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            os_release[k.strip()] = v.strip().strip('"')
    info["os_name"] = os_release.get("PRETTY_NAME") or os_release.get("NAME", "Unknown Linux")
    info["os_version"] = os_release.get("VERSION", os_release.get("VERSION_ID", ""))
    info["os_id"] = os_release.get("ID", "linux")

    # Users with interactive shells
    shell_users = []
    passwd_raw = _run("cat /etc/passwd 2>/dev/null")
    for line in passwd_raw.splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            username = parts[0]
            shell = parts[6]
            uid_val = parts[2]
            # Include users with real shells (not /sbin/nologin, /bin/false, etc.)
            if shell not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin",
                             "/bin/sync", "/bin/halt", "/sbin/shutdown", ""):
                shell_users.append({"user": username, "uid": uid_val, "shell": shell})
    info["shell_users"] = shell_users

    # PATH environment variable (useful for detecting PATH hijacking risk)
    info["env_path"] = os.environ.get("PATH", _run("echo $PATH"))

    # Check for interesting environment variables
    info["sudo_version"] = _run("sudo --version 2>/dev/null | head -1")

    # Home directory
    info["home_dir"] = os.path.expanduser("~")

    return info


def format_summary(info):
    """Return a formatted one-line summary of system info for report headers."""
    return (
        f"Host: {info.get('hostname', 'N/A')}  |  "
        f"User: {info.get('current_user', 'N/A')}  |  "
        f"Kernel: {info.get('kernel_release', 'N/A')}  |  "
        f"OS: {info.get('os_name', 'N/A')}"
    )
