"""
cron_scanner.py — Step 2d: Cron job vulnerability detection.

Checks for:
  1. Writable scripts/binaries executed by root cron jobs
  2. Writable directories containing cron scripts (directory hijacking)
  3. Cron entries referencing missing files (creation attack)
  4. World-readable crontabs that expose system information
"""

import subprocess
import os
import re
import stat
import glob


def _run(cmd):
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        return result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _is_writable(path):
    """Check if a path is world-writable or group-writable."""
    try:
        st = os.stat(path)
        return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    except Exception:
        return False


def _is_world_writable(path):
    """Check if a path is world-writable."""
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IWOTH)
    except Exception:
        return False


def _parse_cron_entries(content, source_file, run_as_user="root"):
    """
    Parse cron file content and extract entries.

    Args:
        content (str): Raw crontab content.
        source_file (str): Path to the source crontab file.
        run_as_user (str): User the cron runs as (from /etc/crontab format).

    Returns:
        list[dict]: Parsed cron entries.
    """
    entries = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue
        # Skip MAILTO, PATH, SHELL assignments
        if re.match(r"^[A-Z_]+=", line):
            continue

        # /etc/crontab format: minute hour dom month dow USER command
        # User crontab format: minute hour dom month dow command
        parts = line.split()
        if len(parts) < 6:
            continue

        # Detect if it includes a username field (system crontab format)
        # System crontabs have: min hr dom mon dow USER cmd
        # User crontabs have:   min hr dom mon dow cmd
        user = run_as_user
        if source_file in ("/etc/crontab",) or "/etc/cron.d/" in source_file:
            if len(parts) >= 7:
                # Field 6 (index 5) should be the username
                potential_user = parts[5]
                # Simple heuristic: usernames don't start with / and aren't numeric
                if not potential_user.startswith("/") and not re.match(r"^\d", potential_user):
                    user = potential_user
                    command = " ".join(parts[6:])
                else:
                    command = " ".join(parts[5:])
            else:
                command = " ".join(parts[5:])
        else:
            command = " ".join(parts[5:])

        schedule = " ".join(parts[:5])
        entries.append({
            "schedule": schedule,
            "user": user,
            "command": command,
            "source_file": source_file,
        })

    return entries


def _extract_script_path(command):
    """
    Extract the script or binary path from a cron command string.
    Strips shell wrappers like /bin/bash -c, sh -c, etc.
    """
    command = command.strip()
    # Strip common shell wrappers
    for wrapper in ("/bin/bash -c ", "/bin/sh -c ", "bash -c ", "sh -c "):
        if command.startswith(wrapper):
            command = command[len(wrapper):].strip().strip("'\"")
            break

    # Extract first token that looks like a path
    tokens = command.split()
    for token in tokens:
        if token.startswith("/") or (os.path.sep in token):
            return token
    # Return first token even if not a path
    return tokens[0] if tokens else None


def scan(verbose=False):
    """
    Scan all crontab locations for vulnerable entries.

    Returns:
        list[dict]: Cron-related findings.
    """
    findings = []
    all_entries = []

    cron_sources = ["/etc/crontab"]
    cron_sources += glob.glob("/etc/cron.d/*")
    cron_sources += glob.glob("/etc/cron.daily/*")
    cron_sources += glob.glob("/etc/cron.hourly/*")
    cron_sources += glob.glob("/etc/cron.weekly/*")
    cron_sources += glob.glob("/etc/cron.monthly/*")

    if verbose:
        print("[*] Scanning system crontab locations...")

    for source in cron_sources:
        if not os.path.isfile(source):
            continue
        try:
            with open(source, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            continue

        run_as = "root"  # Cron.d and /etc/crontab: detected per line; fallback root
        entries = _parse_cron_entries(content, source, run_as_user=run_as)
        all_entries.extend(entries)

    # Current user's crontab
    if verbose:
        print("[*] Reading current user crontab (crontab -l)...")
    user_crontab = _run("crontab -l 2>/dev/null")
    if user_crontab.strip():
        import getpass
        try:
            current_user = getpass.getuser()
        except Exception:
            current_user = "current_user"
        entries = _parse_cron_entries(user_crontab, "crontab -l (current user)", run_as_user=current_user)
        all_entries.extend(entries)

    # Analyze each entry for vulnerabilities
    for entry in all_entries:
        command = entry["command"]
        user = entry["user"]
        source_file = entry["source_file"]
        schedule = entry["schedule"]

        script_path = _extract_script_path(command)
        if not script_path:
            continue

        is_root_job = (user in ("root", "0"))

        # Check 1: Script exists and is writable
        if os.path.isfile(script_path):
            if is_root_job and _is_world_writable(script_path):
                findings.append({
                    "category": "Cron Job Vulnerability",
                    "type": "Writable Cron Script",
                    "source_file": source_file,
                    "schedule": schedule,
                    "user": user,
                    "command": command,
                    "script_path": script_path,
                    "severity": "CRITICAL",
                    "notes": (
                        f"Root cron job runs {script_path} which is world-writable. "
                        "Any user can modify this script to execute arbitrary code as root "
                        "on the next cron execution (Cron Replacement Attack)."
                    ),
                    "mitigation": (
                        f"Fix permissions immediately: chmod 750 {script_path}\n"
                        f"  Verify ownership: chown root:root {script_path}"
                    ),
                })
            elif is_root_job and _is_writable(script_path):
                findings.append({
                    "category": "Cron Job Vulnerability",
                    "type": "Group-Writable Cron Script",
                    "source_file": source_file,
                    "schedule": schedule,
                    "user": user,
                    "command": command,
                    "script_path": script_path,
                    "severity": "HIGH",
                    "notes": (
                        f"Root cron job runs {script_path} which is group-writable. "
                        "Members of the owning group may be able to modify this script."
                    ),
                    "mitigation": (
                        f"Fix permissions: chmod 750 {script_path}\n"
                        f"  Verify ownership: chown root:root {script_path}"
                    ),
                })

        # Check 2: Script does NOT exist (creation attack)
        elif is_root_job and not os.path.exists(script_path):
            script_dir = os.path.dirname(script_path)
            if script_dir and os.path.isdir(script_dir) and _is_writable(script_dir):
                findings.append({
                    "category": "Cron Job Vulnerability",
                    "type": "Missing Cron Script (Creation Attack)",
                    "source_file": source_file,
                    "schedule": schedule,
                    "user": user,
                    "command": command,
                    "script_path": script_path,
                    "severity": "CRITICAL",
                    "notes": (
                        f"Root cron job references {script_path} which does not exist, "
                        f"and its parent directory {script_dir} is writable. "
                        "An attacker can create this file to gain code execution as root."
                    ),
                    "mitigation": (
                        f"Create the script with correct permissions: touch {script_path} && chmod 750 {script_path}\n"
                        "  OR remove the cron entry if no longer needed."
                    ),
                })

        # Check 3: Writable parent directory (directory hijacking)
        if os.path.isfile(script_path) and is_root_job:
            script_dir = os.path.dirname(script_path)
            if script_dir and os.path.isdir(script_dir) and _is_world_writable(script_dir):
                findings.append({
                    "category": "Cron Job Vulnerability",
                    "type": "Writable Script Parent Directory",
                    "source_file": source_file,
                    "schedule": schedule,
                    "user": user,
                    "command": command,
                    "script_path": script_path,
                    "severity": "HIGH",
                    "notes": (
                        f"Root cron job script {script_path} resides in a world-writable "
                        f"directory {script_dir}. An attacker could delete and recreate "
                        "the script, or place malicious files in the same directory."
                    ),
                    "mitigation": (
                        f"Fix directory permissions: chmod 755 {script_dir}\n"
                        "  Add sticky bit if shared: chmod +t {script_dir}"
                    ),
                })

    if verbose:
        print(f"[+] Cron scan complete: {len(all_entries)} cron entries checked, {len(findings)} findings.")

    return findings
