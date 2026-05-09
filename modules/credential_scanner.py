"""
credential_scanner.py — Step 2g: Credential and secret exposure scanner.

Searches for exposed credentials, secrets, and sensitive data:
  - Shell history files containing passwords or secrets
  - .env files with API keys / secrets
  - Hardcoded credentials in config files
  - AWS / GCP / API key patterns
  - Readable SSH private keys
  - World-readable sensitive files
  - Database connection strings
"""

import os
import re
import glob
import stat

# ── Patterns ──────────────────────────────────────────────────────────────────

# Regex patterns that suggest a credential is present in a line
CREDENTIAL_PATTERNS = [
    # Generic key=value password patterns (case-insensitive)
    (re.compile(r'(?i)(password|passwd|pass|pwd)\s*[=:]\s*\S+'), "Password in config"),
    (re.compile(r'(?i)(secret|api_?key|auth_?token|access_?token)\s*[=:]\s*\S+'), "Secret/API key"),
    (re.compile(r'(?i)(db_pass|database_password|mysql_pwd|pg_password)\s*[=:]\s*\S+'), "Database credential"),

    # AWS / cloud credentials
    (re.compile(r'(?i)aws_?secret_?access_?key\s*[=:]\s*\S+'), "AWS secret key"),
    (re.compile(r'(?i)aws_?access_?key_?id\s*[=:]\s*[A-Z0-9]{16,}'), "AWS access key ID"),
    (re.compile(r'(?i)(gcp|google)_?(service_account|api_key|credentials)\s*[=:]\s*\S+'), "GCP credential"),

    # Generic high-entropy secret-like strings (base64 or hex, ≥32 chars)
    (re.compile(r'(?i)(token|secret|key|password)\s*[=:]\s*[A-Za-z0-9+/=_\-]{32,}'), "Long secret value"),

    # Connection strings
    (re.compile(r'(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@]+@'), "Database connection string"),

    # Private key header
    (re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'), "Embedded private key"),
]

# History command patterns suggesting credential exposure
HISTORY_PATTERNS = [
    re.compile(r'(?i)\b(curl|wget)\b.*(-u|--user)\s+\S+:\S+'),          # curl -u user:pass
    re.compile(r'(?i)\b(mysql|psql|mongo)\b.*-p\s*\S'),                   # mysql -pPASS
    re.compile(r'(?i)\bexport\b.*\b(password|secret|key|token)\b.*=\s*\S+'),  # export SECRET=value
    re.compile(r'(?i)sshpass\s+-p\s+\S+'),                                # sshpass -p
    re.compile(r'(?i)\bpasswd\b.*--stdin'),                                # passwd --stdin
    re.compile(r'(?i)\bftp\b.*\b(user|login|pass)\b'),                    # ftp credentials
]

# Files and directories to search for credentials
HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".fish_history",
    ".python_history",
    ".mysql_history",
    ".psql_history",
    ".mongocli_history",
]

# Config file globs to scan for hardcoded credentials
CONFIG_GLOBS = [
    "/etc/*.conf",
    "/etc/*.cfg",
    "/etc/**/*.conf",
    "/etc/**/*.cfg",
    "/var/www/**/*.php",
    "/var/www/**/*.env",
    "/opt/**/*.conf",
    "/opt/**/*.cfg",
    "/home/**/.env",
    "/root/.env",
    "/home/**/*.conf",
    "/home/**/*.cfg",
]

# Sensitive files that should not be world-readable
SENSITIVE_FILES = [
    ("/etc/shadow",           "Shadow password file",        "CRITICAL"),
    ("/etc/gshadow",          "Group shadow file",           "HIGH"),
    ("/etc/mysql/debian.cnf", "MySQL maintenance credential","HIGH"),
    ("/root/.ssh/id_rsa",     "Root SSH private key",        "CRITICAL"),
    ("/root/.ssh/id_ecdsa",   "Root SSH private key (EC)",   "CRITICAL"),
    ("/root/.ssh/id_ed25519", "Root SSH private key (Ed25519)", "CRITICAL"),
    ("/root/.aws/credentials","AWS root credentials",        "CRITICAL"),
    ("/root/.gnupg",          "GPG private keyring",         "HIGH"),
]

# Max bytes to read per file (avoid reading huge files)
MAX_FILE_BYTES = 256 * 1024   # 256 KB
MAX_LINE_LEN   = 500           # Truncate long lines in output


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_readable(path):
    """Return True if path exists and is readable by current user."""
    try:
        return os.path.isfile(path) and os.access(path, os.R_OK)
    except OSError:
        return False


def _read_lines(path, max_bytes=MAX_FILE_BYTES):
    """Read lines from a file safely, up to max_bytes."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes).splitlines()
    except (OSError, PermissionError):
        return []


def _truncate(line, n=MAX_LINE_LEN):
    return line[:n] + ("…" if len(line) > n else "")


def _stat_mode(path):
    """Return octal permission string or None."""
    try:
        return oct(stat.S_IMODE(os.stat(path).st_mode))
    except OSError:
        return None


def _world_readable(path):
    """Return True if the file is world-readable."""
    try:
        return bool(os.stat(path).st_mode & stat.S_IROTH)
    except OSError:
        return False


# ── Sub-scanners ──────────────────────────────────────────────────────────────

def _scan_history_files(verbose):
    """Scan shell history files for credential exposure."""
    findings = []

    # Collect candidate history paths from all home directories and root
    home_dirs = []
    try:
        for entry in os.scandir("/home"):
            if entry.is_dir():
                home_dirs.append(entry.path)
    except OSError:
        pass
    home_dirs.append("/root")

    for home in home_dirs:
        for hist_name in HISTORY_FILES:
            hist_path = os.path.join(home, hist_name)
            if not _is_readable(hist_path):
                continue

            if verbose:
                print(f"      [history] {hist_path}")

            lines = _read_lines(hist_path)
            hits = []
            for lineno, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                for pattern in HISTORY_PATTERNS:
                    if pattern.search(line):
                        hits.append(f"Line {lineno}: {_truncate(line)}")
                        break  # one hit per line is enough

            if hits:
                sample = hits[:5]
                notes_lines = ["Shell history contains commands that may expose credentials:", ""]
                notes_lines += [f"  {h}" for h in sample]
                if len(hits) > 5:
                    notes_lines.append(f"  … and {len(hits) - 5} more matching lines.")

                findings.append({
                    "category": "Credentials",
                    "type": "Credential in Shell History",
                    "severity": "HIGH",
                    "path": hist_path,
                    "notes": "\n".join(notes_lines),
                    "mitigation": (
                        "Clear shell history: history -c && > ~/.bash_history\n"
                        "Set HISTFILE=/dev/null in your profile to disable history.\n"
                        "Rotate any credentials exposed in history immediately."
                    ),
                })

    return findings


def _scan_env_files(verbose):
    """Scan .env files for secrets."""
    findings = []

    env_paths = []
    # Common .env locations
    for pattern in ["/home/**/.env", "/root/.env", "/var/www/**/.env", "/opt/**/.env", "/srv/**/.env"]:
        try:
            env_paths.extend(glob.glob(pattern, recursive=True))
        except Exception:
            pass

    for env_path in env_paths:
        if not _is_readable(env_path):
            continue

        if verbose:
            print(f"      [env] {env_path}")

        lines = _read_lines(env_path)
        hits = []
        for lineno, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for pattern, label in CREDENTIAL_PATTERNS:
                if pattern.search(line):
                    hits.append(f"Line {lineno} [{label}]: {_truncate(line)}")
                    break

        if hits:
            notes_lines = [f"Secrets found in environment file ({env_path}):", ""]
            notes_lines += [f"  {h}" for h in hits[:8]]
            if len(hits) > 8:
                notes_lines.append(f"  … and {len(hits) - 8} more.")

            findings.append({
                "category": "Credentials",
                "type": "Secret in .env File",
                "severity": "HIGH",
                "path": env_path,
                "permissions": _stat_mode(env_path),
                "notes": "\n".join(notes_lines),
                "mitigation": (
                    "Restrict permissions: chmod 600 " + env_path + "\n"
                    "Use a secrets manager (Vault, AWS Secrets Manager) instead of .env files.\n"
                    "Ensure .env is in .gitignore if the directory is a git repo."
                ),
            })
        elif _world_readable(env_path):
            # Even an empty/harmless .env shouldn't be world-readable
            findings.append({
                "category": "Credentials",
                "type": "World-Readable .env File",
                "severity": "MEDIUM",
                "path": env_path,
                "permissions": _stat_mode(env_path),
                "notes": "Environment file is world-readable. Any secrets it contains are exposed to all local users.",
                "mitigation": f"chmod 600 {env_path}",
            })

    return findings


def _scan_config_files(verbose):
    """Scan config files for hardcoded credentials."""
    findings = []
    scanned = set()

    for pattern in CONFIG_GLOBS:
        try:
            paths = glob.glob(pattern, recursive=True)
        except Exception:
            continue

        for cfg_path in paths:
            if cfg_path in scanned:
                continue
            scanned.add(cfg_path)

            if not _is_readable(cfg_path):
                continue
            if os.path.getsize(cfg_path) == 0:
                continue

            if verbose:
                print(f"      [config] {cfg_path}")

            lines = _read_lines(cfg_path)
            hits = []
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                    continue
                for pattern_re, label in CREDENTIAL_PATTERNS:
                    if pattern_re.search(stripped):
                        hits.append(f"Line {lineno} [{label}]: {_truncate(stripped)}")
                        break

            if hits:
                severity = "CRITICAL" if "/etc/" in cfg_path else "HIGH"
                notes_lines = ["Hardcoded credentials detected in config file:", ""]
                notes_lines += [f"  {h}" for h in hits[:6]]
                if len(hits) > 6:
                    notes_lines.append(f"  … and {len(hits) - 6} more.")

                findings.append({
                    "category": "Credentials",
                    "type": "Hardcoded Credential in Config",
                    "severity": severity,
                    "path": cfg_path,
                    "permissions": _stat_mode(cfg_path),
                    "notes": "\n".join(notes_lines),
                    "mitigation": (
                        "Replace hardcoded credentials with environment variables or\n"
                        "a secrets management solution.\n"
                        "Restrict file permissions: chmod 640 " + cfg_path
                    ),
                })

    return findings


def _scan_ssh_keys(verbose):
    """Check for readable SSH private keys and weak configurations."""
    findings = []

    # Scan all home directories + root for SSH keys
    home_dirs = []
    try:
        for entry in os.scandir("/home"):
            if entry.is_dir():
                home_dirs.append(entry.path)
    except OSError:
        pass
    home_dirs.append("/root")

    key_names = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss"]

    for home in home_dirs:
        ssh_dir = os.path.join(home, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue

        # Check .ssh dir permissions
        try:
            ssh_mode = stat.S_IMODE(os.stat(ssh_dir).st_mode)
            if ssh_mode & (stat.S_IRWXG | stat.S_IRWXO):
                findings.append({
                    "category": "Credentials",
                    "type": "Insecure SSH Directory Permissions",
                    "severity": "HIGH",
                    "path": ssh_dir,
                    "permissions": oct(ssh_mode),
                    "notes": (
                        f".ssh directory has too-permissive permissions ({oct(ssh_mode)}).\n"
                        "SSH will refuse to use keys if the directory is group/world readable."
                    ),
                    "mitigation": f"chmod 700 {ssh_dir}",
                })
        except OSError:
            pass

        for key_name in key_names:
            key_path = os.path.join(ssh_dir, key_name)
            if not os.path.isfile(key_path):
                continue

            if verbose:
                print(f"      [ssh key] {key_path}")

            try:
                key_mode = stat.S_IMODE(os.stat(key_path).st_mode)
                world_read = bool(key_mode & stat.S_IROTH)
                group_read = bool(key_mode & stat.S_IRGRP)

                # Check if key is password-protected
                lines = _read_lines(key_path, max_bytes=4096)
                encrypted = any("ENCRYPTED" in l or "Proc-Type" in l for l in lines)

                if world_read or group_read:
                    severity = "CRITICAL" if world_read else "HIGH"
                    findings.append({
                        "category": "Credentials",
                        "type": "Exposed SSH Private Key",
                        "severity": severity,
                        "path": key_path,
                        "permissions": oct(key_mode),
                        "notes": (
                            f"SSH private key is readable by {'everyone' if world_read else 'group members'}.\n"
                            f"Key is {'passphrase-protected' if encrypted else 'NOT passphrase-protected — immediate risk'}."
                        ),
                        "mitigation": (
                            f"chmod 600 {key_path}\n"
                            "Use a passphrase on all SSH private keys.\n"
                            "Rotate the key if it has been exposed."
                        ),
                    })
                elif not encrypted:
                    findings.append({
                        "category": "Credentials",
                        "type": "Unencrypted SSH Private Key",
                        "severity": "MEDIUM",
                        "path": key_path,
                        "permissions": oct(key_mode),
                        "notes": (
                            "SSH private key exists without a passphrase.\n"
                            "If this file is copied or the system is compromised, the key is immediately usable."
                        ),
                        "mitigation": (
                            "Add a passphrase: ssh-keygen -p -f " + key_path + "\n"
                            "Consider using ssh-agent to avoid repeated passphrase entry."
                        ),
                    })
            except OSError:
                pass

    return findings


def _scan_sensitive_file_permissions(verbose):
    """Check well-known sensitive files for overly permissive access."""
    findings = []

    for path, description, base_severity in SENSITIVE_FILES:
        if not os.path.exists(path):
            continue

        if verbose:
            print(f"      [sensitive] {path}")

        try:
            file_stat = os.stat(path)
            mode = stat.S_IMODE(file_stat.st_mode)
            world_read = bool(mode & stat.S_IROTH)
            group_read = bool(mode & stat.S_IRGRP)

            if world_read:
                findings.append({
                    "category": "Credentials",
                    "type": "World-Readable Sensitive File",
                    "severity": base_severity,
                    "path": path,
                    "permissions": oct(mode),
                    "notes": (
                        f"{description} is world-readable.\n"
                        "Any local user can read its contents."
                    ),
                    "mitigation": f"chmod o-r {path}",
                })
            elif group_read and path in ("/etc/shadow", "/etc/gshadow"):
                findings.append({
                    "category": "Credentials",
                    "type": "Group-Readable Shadow File",
                    "severity": "HIGH",
                    "path": path,
                    "permissions": oct(mode),
                    "notes": (
                        f"{description} is group-readable.\n"
                        "Members of the shadow group can read password hashes."
                    ),
                    "mitigation": f"chmod 640 {path}  (group should be 'shadow')",
                })
        except OSError:
            pass

    return findings


def _scan_aws_credential_files(verbose):
    """Look for readable AWS credential files."""
    findings = []

    aws_paths = []
    try:
        for entry in os.scandir("/home"):
            if entry.is_dir():
                aws_paths.append(os.path.join(entry.path, ".aws", "credentials"))
                aws_paths.append(os.path.join(entry.path, ".aws", "config"))
    except OSError:
        pass
    aws_paths += ["/root/.aws/credentials", "/root/.aws/config"]

    for aws_path in aws_paths:
        if not _is_readable(aws_path):
            continue

        if verbose:
            print(f"      [aws] {aws_path}")

        mode = _stat_mode(aws_path)
        world_read = _world_readable(aws_path)

        lines = _read_lines(aws_path)
        has_keys = any(
            re.search(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*\S+', l)
            for l in lines
        )

        if has_keys:
            severity = "CRITICAL" if world_read else "HIGH"
            findings.append({
                "category": "Credentials",
                "type": "AWS Credentials File",
                "severity": severity,
                "path": aws_path,
                "permissions": mode,
                "notes": (
                    f"AWS credentials file found with access keys.\n"
                    f"File is {'world-readable — any local user can steal these keys' if world_read else 'readable by current user'}."
                ),
                "mitigation": (
                    f"chmod 600 {aws_path}\n"
                    "Use IAM roles instead of long-lived access keys where possible.\n"
                    "Rotate any exposed keys immediately via the AWS IAM console."
                ),
            })

    return findings


# ── Public API ─────────────────────────────────────────────────────────────────

def scan(verbose=False):
    """
    Run all credential exposure sub-checks.

    Args:
        verbose (bool): Print progress messages.

    Returns:
        list[dict]: Findings with category, type, severity, path, notes, mitigation.
    """
    findings = []

    if verbose:
        print("    [*] Scanning shell history files...")
    findings.extend(_scan_history_files(verbose))

    if verbose:
        print("    [*] Scanning .env files...")
    findings.extend(_scan_env_files(verbose))

    if verbose:
        print("    [*] Scanning config files for hardcoded credentials...")
    findings.extend(_scan_config_files(verbose))

    if verbose:
        print("    [*] Scanning SSH private keys...")
    findings.extend(_scan_ssh_keys(verbose))

    if verbose:
        print("    [*] Checking sensitive file permissions...")
    findings.extend(_scan_sensitive_file_permissions(verbose))

    if verbose:
        print("    [*] Scanning AWS credential files...")
    findings.extend(_scan_aws_credential_files(verbose))

    return findings
