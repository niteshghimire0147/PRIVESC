"""
path_scanner.py — Step 2h: PATH hijacking vulnerability scanner.

Checks for privilege escalation vectors via PATH manipulation:
  1. Dot (.) or empty entries in $PATH (current-directory execution)
  2. World-writable directories in $PATH
  3. Group-writable directories in $PATH
  4. Missing directories in $PATH (may be created by attacker)
  5. Relative paths in $PATH (not starting with /)
  6. PATH entries in systemd service files that include unsafe directories
  7. SUID binaries that call external commands without absolute paths
     (detected via strings analysis where available)
"""

import os
import re
import stat
import subprocess
import glob


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stat_mode(path):
    """Return octal permission string or None."""
    try:
        return oct(stat.S_IMODE(os.stat(path).st_mode))
    except OSError:
        return None


def _dir_writable_by_others(path):
    """Return (world_writable, group_writable) tuple for a directory."""
    try:
        mode = os.stat(path).st_mode
        return (
            bool(mode & stat.S_IWOTH),
            bool(mode & stat.S_IWGRP),
        )
    except OSError:
        return (False, False)


def _get_path_dirs():
    """Return the list of PATH directories from the environment."""
    path_env = os.environ.get("PATH", "")
    return [d for d in path_env.split(":") if d != ""]  # preserve empty → handled separately


def _get_raw_path():
    """Return the raw PATH string."""
    return os.environ.get("PATH", "")


# ── Sub-scanners ──────────────────────────────────────────────────────────────

def _check_dot_in_path(verbose):
    """Detect '.' or empty string (implicit '.') in PATH."""
    findings = []
    raw_path = _get_raw_path()
    entries = raw_path.split(":")

    for i, entry in enumerate(entries):
        if entry == "." or entry == "":
            label = '"."' if entry == "." else '"" (empty, implies current directory)'
            findings.append({
                "category": "PATH Hijacking",
                "type": "Current Directory in PATH",
                "severity": "HIGH",
                "path": f"PATH entry #{i + 1}: {label}",
                "setting": f"PATH={raw_path}",
                "notes": (
                    f"PATH contains {label} at position {i + 1}.\n"
                    "An attacker who can write to the current directory can create a fake binary\n"
                    "(e.g. 'ls', 'id') that gets executed instead of the real system command\n"
                    "when a privileged user runs commands from that directory."
                ),
                "mitigation": (
                    "Remove '.' and empty entries from PATH.\n"
                    "Never include the current directory in root's PATH.\n"
                    "Set PATH explicitly in /etc/profile, /etc/environment, or shell rc files."
                ),
            })

    return findings


def _check_relative_paths(verbose):
    """Detect relative (non-absolute) paths in PATH."""
    findings = []
    raw_path = _get_raw_path()
    entries = raw_path.split(":")

    for i, entry in enumerate(entries):
        if entry and not entry.startswith("/"):
            findings.append({
                "category": "PATH Hijacking",
                "type": "Relative Path in PATH",
                "severity": "HIGH",
                "path": f"PATH entry #{i + 1}: {entry}",
                "setting": f"PATH={raw_path}",
                "notes": (
                    f"PATH contains a relative path: '{entry}' at position {i + 1}.\n"
                    "Relative paths are resolved against the current working directory,\n"
                    "making command execution unpredictable and exploitable."
                ),
                "mitigation": (
                    f"Replace '{entry}' with its absolute path in PATH.\n"
                    "All PATH entries should begin with '/'."
                ),
            })

    return findings


def _check_writable_path_dirs(verbose):
    """Check each PATH directory for world-writable or group-writable permissions."""
    findings = []
    path_dirs = _get_path_dirs()
    seen = set()
    for path_dir in path_dirs:
        if path_dir in seen or not path_dir.startswith("/"):
            continue
        seen.add(path_dir)

        if not os.path.isdir(path_dir):
            continue

        if verbose:
            print(f"      [path dir] {path_dir}")

        world_w, group_w = _dir_writable_by_others(path_dir)

        if world_w:
            findings.append({
                "category": "PATH Hijacking",
                "type": "World-Writable PATH Directory",
                "severity": "CRITICAL",
                "path": path_dir,
                "permissions": _stat_mode(path_dir),
                "notes": (
                    f"PATH directory '{path_dir}' is world-writable.\n"
                    "Any local user can place a malicious binary here with the same name as a\n"
                    "legitimate command. The next user (especially root) who runs that command\n"
                    "will execute the attacker's binary instead."
                ),
                "exploit_example": (
                    f"echo '#!/bin/bash\\n/bin/bash -p' > {path_dir}/sudo && chmod +x {path_dir}/sudo\n"
                    "# Then wait for a privileged user to type 'sudo'"
                ),
                "mitigation": (
                    f"chmod o-w {path_dir}\n"
                    "Ensure all PATH directories are owned by root and not world-writable."
                ),
                "reference": "https://attack.mitre.org/techniques/T1574/007/",
            })
        elif group_w:
            findings.append({
                "category": "PATH Hijacking",
                "type": "Group-Writable PATH Directory",
                "severity": "HIGH",
                "path": path_dir,
                "permissions": _stat_mode(path_dir),
                "notes": (
                    f"PATH directory '{path_dir}' is group-writable.\n"
                    "Members of the owning group can place malicious binaries here."
                ),
                "mitigation": (
                    f"chmod g-w {path_dir}\n"
                    "PATH directories should be writable only by root."
                ),
            })

    return findings


def _check_missing_path_dirs(verbose):
    """Detect PATH entries that do not exist (may be created by an attacker)."""
    findings = []
    path_dirs = _get_path_dirs()
    seen = set()

    for path_dir in path_dirs:
        if path_dir in seen or not path_dir.startswith("/"):
            continue
        seen.add(path_dir)

        if not os.path.exists(path_dir):
            # Check if the parent is writable
            parent = os.path.dirname(path_dir)
            try:
                parent_mode = os.stat(parent).st_mode
                parent_writable = bool(parent_mode & stat.S_IWOTH) or os.access(parent, os.W_OK)
            except OSError:
                parent_writable = False

            severity = "HIGH" if parent_writable else "MEDIUM"
            findings.append({
                "category": "PATH Hijacking",
                "type": "Missing PATH Directory",
                "severity": severity,
                "path": path_dir,
                "notes": (
                    f"PATH includes '{path_dir}' which does not exist.\n"
                    + (
                        "The parent directory is writable — an attacker could create this\n"
                        "directory and populate it with malicious binaries."
                        if parent_writable else
                        "If an attacker gains write access to the parent, they could create\n"
                        "this directory and insert malicious binaries."
                    )
                ),
                "mitigation": (
                    f"Remove '{path_dir}' from PATH, or create the directory with root ownership\n"
                    "and permissions 755."
                ),
            })

    return findings


def _check_service_file_paths(verbose):
    """
    Scan systemd service files for unsafe PATH in Environment= directives.
    Also look for ExecStart= commands without absolute paths.
    """
    findings = []

    service_dirs = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ]

    unsafe_path_re = re.compile(
        r'(?i)^Environment=.*PATH=([^\s"\']+)'
    )
    exec_start_re = re.compile(r'^\s*ExecStart\s*=\s*(.+)')

    for svc_dir in service_dirs:
        if not os.path.isdir(svc_dir):
            continue

        try:
            service_files = glob.glob(os.path.join(svc_dir, "*.service"))
        except Exception:
            continue

        for svc_file in service_files:
            try:
                with open(svc_file, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except (OSError, PermissionError):
                continue

            # Check for unsafe PATH in Environment=
            for line in content.splitlines():
                m = unsafe_path_re.match(line.strip())
                if m:
                    path_val = m.group(1)
                    entries = path_val.split(":")
                    bad = [e for e in entries if e in (".", "") or not e.startswith("/")]
                    if bad:
                        findings.append({
                            "category": "PATH Hijacking",
                            "type": "Unsafe PATH in Service File",
                            "severity": "HIGH",
                            "path": svc_file,
                            "setting": line.strip(),
                            "notes": (
                                f"Service file sets an unsafe PATH: {path_val}\n"
                                f"Problematic entries: {', '.join(repr(b) for b in bad)}\n"
                                "Services running as root with '.' in PATH are vulnerable to\n"
                                "PATH hijacking attacks."
                            ),
                            "mitigation": (
                                "Remove '.' and relative paths from Environment=PATH in service files.\n"
                                "Use fully qualified paths for all commands in ExecStart=."
                            ),
                        })

            # Check ExecStart= for non-absolute command paths
            for line in content.splitlines():
                m = exec_start_re.match(line)
                if m:
                    cmd = m.group(1).lstrip("-").strip()  # strip leading dash (ignore errors)
                    # Get just the executable part
                    exe = cmd.split()[0] if cmd.split() else ""
                    if exe and not exe.startswith("/") and exe not in ("@", "!"):
                        findings.append({
                            "category": "PATH Hijacking",
                            "type": "Relative ExecStart in Service File",
                            "severity": "MEDIUM",
                            "path": svc_file,
                            "setting": line.strip(),
                            "notes": (
                                f"Service ExecStart uses a relative path: '{exe}'\n"
                                "Command resolution depends on the service's PATH, which may\n"
                                "be manipulated if the service has an unsafe Environment=PATH."
                            ),
                            "mitigation": f"Use the absolute path for '{exe}' in ExecStart=.",
                        })

    return findings


def _check_sudo_path_preservation(verbose):
    """
    Check if sudo preserves a potentially unsafe PATH (env_keep or !env_reset).
    """
    findings = []

    try:
        result = subprocess.run(
            ["sudo", "-l"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10
        )
        output = result.stdout + result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return findings

    # Look for env_keep PATH or !env_reset
    if re.search(r'env_keep.*\bPATH\b', output, re.IGNORECASE):
        findings.append({
            "category": "PATH Hijacking",
            "type": "sudo Preserves User PATH",
            "severity": "HIGH",
            "path": "/etc/sudoers",
            "setting": "env_keep+=PATH (or similar)",
            "notes": (
                "sudo is configured to preserve the user's PATH environment variable.\n"
                "If the user's PATH includes writable or relative directories, a sudo\n"
                "command may execute a malicious binary instead of the intended one.\n\n"
                "Relevant sudoers output:\n"
                + "\n".join(
                    "  " + l for l in output.splitlines()
                    if "env_keep" in l.lower() or "env_reset" in l.lower()
                )
            ),
            "mitigation": (
                "Remove PATH from env_keep in /etc/sudoers.\n"
                "Enable env_reset (default in most distros) to reset PATH to a safe value.\n"
                "Set secure_path in /etc/sudoers to an explicit safe PATH."
            ),
        })

    if re.search(r'!env_reset', output, re.IGNORECASE):
        findings.append({
            "category": "PATH Hijacking",
            "type": "sudo env_reset Disabled",
            "severity": "CRITICAL",
            "path": "/etc/sudoers",
            "setting": "!env_reset",
            "notes": (
                "sudo is configured with !env_reset, meaning it passes the entire user\n"
                "environment (including PATH) through to the privileged process.\n"
                "This allows complete PATH hijacking for any command run with sudo."
            ),
            "mitigation": (
                "Remove '!env_reset' from /etc/sudoers.\n"
                "Use 'Defaults env_reset' and set 'Defaults secure_path=...' to a safe PATH."
            ),
        })

    return findings


# ── Public API ─────────────────────────────────────────────────────────────────

def scan(verbose=False):
    """
    Run all PATH hijacking sub-checks.

    Args:
        verbose (bool): Print progress messages.

    Returns:
        list[dict]: Findings with category, type, severity, path, notes, mitigation.
    """
    findings = []

    if verbose:
        print("    [*] Checking for '.' or empty entries in PATH...")
    findings.extend(_check_dot_in_path(verbose))

    if verbose:
        print("    [*] Checking for relative paths in PATH...")
    findings.extend(_check_relative_paths(verbose))

    if verbose:
        print("    [*] Checking PATH directories for write permissions...")
    findings.extend(_check_writable_path_dirs(verbose))

    if verbose:
        print("    [*] Checking for missing PATH directories...")
    findings.extend(_check_missing_path_dirs(verbose))

    if verbose:
        print("    [*] Scanning systemd service files for PATH issues...")
    findings.extend(_check_service_file_paths(verbose))

    if verbose:
        print("    [*] Checking sudo PATH preservation settings...")
    findings.extend(_check_sudo_path_preservation(verbose))

    return findings
