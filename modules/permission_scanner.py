"""
permission_scanner.py — Step 2b: Weak file and directory permissions.

Checks for:
  1. World-writable files (especially in sensitive directories)
  2. World-writable directories
  3. Critical system file permissions (/etc/passwd, /etc/shadow, /etc/sudoers)
  4. Overly permissive home directories
"""

import subprocess
import os
import stat


def _run(cmd):
    """Run a shell command and return stdout lines."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        output = result.stdout.decode("utf-8", errors="replace").strip()
        return [line.strip() for line in output.splitlines() if line.strip()]
    except Exception:
        return []


def _get_octal_perms(path):
    """Return the octal permission string for a path, e.g. '0777'."""
    try:
        st = os.stat(path)
        return oct(stat.S_IMODE(st.st_mode))
    except Exception:
        return None


def _get_owner(path):
    """Return (uid, gid) for a path."""
    try:
        st = os.stat(path)
        return st.st_uid, st.st_gid
    except Exception:
        return None, None


# Directories to exclude from world-writable scans (always noisy/intentional)
EXCLUDED_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp",
                 "/dev/shm", "/snap"}

# Sensitive directories — world-writable files here are CRITICAL
SENSITIVE_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
                  "/lib", "/usr/lib", "/boot", "/usr/local/bin",
                  "/usr/local/sbin"]


def _is_excluded(path):
    """Check if a path falls under an excluded directory."""
    for excluded in EXCLUDED_DIRS:
        if path.startswith(excluded + "/") or path == excluded:
            return True
    return False


def _is_sensitive(path):
    """Check if a path falls under a sensitive directory."""
    for sensitive in SENSITIVE_DIRS:
        if path.startswith(sensitive + "/") or path == sensitive:
            return True
    return False


def _scan_world_writable_files(verbose=False):
    """Find world-writable files outside of temp/proc/sys directories."""
    findings = []
    if verbose:
        print("[*] Scanning for world-writable files...")

    paths = _run(
        "find / -perm -o+w -not -type l -type f 2>/dev/null"
    )

    for path in paths:
        if _is_excluded(path):
            continue

        perms = _get_octal_perms(path)
        uid, gid = _get_owner(path)

        if _is_sensitive(path):
            severity = "CRITICAL"
            notes = (
                f"World-writable file in sensitive directory {os.path.dirname(path)}. "
                "Any user can modify this file, potentially affecting system integrity."
            )
        else:
            severity = "MEDIUM"
            notes = "World-writable file outside of system directories. May be writable by unintended users."

        findings.append({
            "category": "Weak File Permissions",
            "type": "World-Writable File",
            "path": path,
            "permissions": perms,
            "owner_uid": uid,
            "severity": severity,
            "notes": notes,
            "mitigation": (
                f"Restrict permissions: chmod o-w {path}\n"
                "  Verify what process writes to this file and whether world-write is intentional."
            ),
        })

    return findings


def _scan_world_writable_dirs(verbose=False):
    """Find world-writable directories (excluding sticky-bit protected ones)."""
    findings = []
    if verbose:
        print("[*] Scanning for world-writable directories...")

    # -perm -o+w = world writable; filter out sticky-bit dirs (like /tmp)
    paths = _run(
        "find / -perm -o+w -type d -not -perm -1000 2>/dev/null"
    )

    for path in paths:
        if _is_excluded(path):
            continue

        perms = _get_octal_perms(path)
        uid, gid = _get_owner(path)

        if _is_sensitive(path):
            severity = "CRITICAL"
            notes = (
                "World-writable directory in sensitive location. "
                "An attacker can plant malicious files or scripts here."
            )
        else:
            severity = "MEDIUM"
            notes = "World-writable directory without sticky bit. Files can be created or overwritten by any user."

        findings.append({
            "category": "Weak File Permissions",
            "type": "World-Writable Directory",
            "path": path,
            "permissions": perms,
            "owner_uid": uid,
            "severity": severity,
            "notes": notes,
            "mitigation": (
                f"Add sticky bit: chmod +t {path}  OR  Restrict permissions: chmod o-w {path}\n"
                "  Sticky bit prevents users from deleting other users' files."
            ),
        })

    return findings


def _check_critical_files(verbose=False):
    """Check permissions on /etc/passwd, /etc/shadow, /etc/sudoers, etc."""
    findings = []
    if verbose:
        print("[*] Checking critical file permissions...")

    critical_files = [
        {
            "path": "/etc/passwd",
            "expected_perms": ["0o644"],
            "expected_owner": 0,  # root uid
            "severity_if_wrong": "HIGH",
            "notes_template": "/etc/passwd has permissions {perms} (expected 644). "
                              "If world-writable, any user can add a root account.",
        },
        {
            "path": "/etc/shadow",
            "expected_perms": ["0o640", "0o000", "0o600"],
            "expected_owner": 0,
            "severity_if_wrong": "CRITICAL",
            "notes_template": "/etc/shadow has permissions {perms} (expected 640 or 000). "
                              "If readable, password hashes can be extracted and cracked.",
        },
        {
            "path": "/etc/sudoers",
            "expected_perms": ["0o440", "0o400"],
            "expected_owner": 0,
            "severity_if_wrong": "CRITICAL",
            "notes_template": "/etc/sudoers has permissions {perms} (expected 440). "
                              "If world-writable, any user can grant themselves sudo access.",
        },
        {
            "path": "/etc/sudoers.d",
            "expected_perms": ["0o750", "0o755"],
            "expected_owner": 0,
            "severity_if_wrong": "HIGH",
            "notes_template": "/etc/sudoers.d has permissions {perms} (expected 750 or 755).",
        },
        {
            "path": "/etc/crontab",
            "expected_perms": ["0o644", "0o600"],
            "expected_owner": 0,
            "severity_if_wrong": "HIGH",
            "notes_template": "/etc/crontab has permissions {perms} (expected 644). "
                              "If writable, cron entries can be injected to run as root.",
        },
        {
            "path": "/etc/ssh/sshd_config",
            "expected_perms": ["0o644", "0o600"],
            "expected_owner": 0,
            "severity_if_wrong": "HIGH",
            "notes_template": "/etc/ssh/sshd_config has permissions {perms}. "
                              "If writable, SSH config can be modified to allow unauthorized access.",
        },
    ]

    for entry in critical_files:
        path = entry["path"]
        if not os.path.exists(path):
            continue

        perms = _get_octal_perms(path)
        uid, gid = _get_owner(path)

        if perms is None:
            continue

        # Check if permissions are correct
        perm_ok = perms in entry["expected_perms"]
        owner_ok = (uid == entry["expected_owner"])

        # Check for world-writable specifically (most dangerous)
        try:
            st = os.stat(path)
            world_writable = bool(st.st_mode & stat.S_IWOTH)
            world_readable = bool(st.st_mode & stat.S_IROTH)
        except Exception:
            world_writable = False
            world_readable = False

        issues = []
        if world_writable:
            issues.append("world-writable")
        if not owner_ok:
            issues.append(f"owned by UID {uid} instead of root (UID 0)")

        # /etc/shadow being world-readable is already a CRITICAL issue
        if path == "/etc/shadow" and world_readable:
            issues.append("world-readable (password hashes exposed)")

        if not perm_ok or issues:
            severity = entry["severity_if_wrong"]
            # Escalate to CRITICAL if world-writable
            if world_writable:
                severity = "CRITICAL"

            notes = entry["notes_template"].format(perms=perms)
            if issues:
                notes += f" Issues: {', '.join(issues)}."

            findings.append({
                "category": "Weak File Permissions",
                "type": "Critical System File",
                "path": path,
                "permissions": perms,
                "owner_uid": uid,
                "world_writable": world_writable,
                "severity": severity,
                "notes": notes,
                "mitigation": (
                    f"Fix permissions: chmod {entry['expected_perms'][0].replace('0o', '').zfill(4)} {path}\n"
                    f"  Fix ownership: chown root:root {path}"
                ),
            })

    return findings


def _check_home_directories(verbose=False):
    """Check if home directories are world-readable or world-writable."""
    findings = []
    if verbose:
        print("[*] Checking home directory permissions...")

    home_base = "/home"
    if not os.path.isdir(home_base):
        return findings

    try:
        entries = os.listdir(home_base)
    except OSError:
        return findings

    for entry in entries:
        path = os.path.join(home_base, entry)
        if not os.path.isdir(path):
            continue

        perms = _get_octal_perms(path)
        if perms is None:
            continue

        try:
            st = os.stat(path)
            world_readable = bool(st.st_mode & stat.S_IROTH)
            world_writable = bool(st.st_mode & stat.S_IWOTH)
            world_executable = bool(st.st_mode & stat.S_IXOTH)
        except Exception:
            continue

        if world_writable:
            severity = "CRITICAL"
            notes = (
                f"Home directory {path} is world-writable ({perms}). "
                "An attacker could plant backdoors like .bashrc, .ssh/authorized_keys, or .bash_profile."
            )
        elif world_readable and world_executable:
            severity = "MEDIUM"
            notes = (
                f"Home directory {path} is world-readable ({perms}). "
                "Files like .bash_history, SSH keys, and config files may be exposed."
            )
        else:
            continue  # Permissions are fine

        findings.append({
            "category": "Weak File Permissions",
            "type": "Home Directory",
            "path": path,
            "permissions": perms,
            "severity": severity,
            "notes": notes,
            "mitigation": (
                f"Fix permissions: chmod 700 {path}\n"
                "  Home directories should only be accessible by the owner."
            ),
        })

    return findings


def scan(verbose=False, quick=False):
    """
    Run all permission checks and return combined findings.

    Args:
        verbose (bool): Print progress messages.
        quick (bool): If True, skip slow filesystem-wide find scans and only
                      check critical system files and home directories.

    Returns:
        list[dict]: All permission-related findings.
    """
    findings = []

    if not quick:
        findings.extend(_scan_world_writable_files(verbose=verbose))
        findings.extend(_scan_world_writable_dirs(verbose=verbose))
    elif verbose:
        print("[i] Quick mode: skipping world-writable filesystem scan.")

    findings.extend(_check_critical_files(verbose=verbose))
    findings.extend(_check_home_directories(verbose=verbose))

    if verbose:
        print(f"[+] Permission scan complete: {len(findings)} findings.")

    return findings
