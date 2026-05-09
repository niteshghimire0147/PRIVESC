"""
ssh_scanner.py — Agentless remote Linux scanning via SSH.

Connects to a remote Linux host using Paramiko, uploads a self-contained
scan script, executes it, and retrieves the structured JSON results —
no agent installation required on the target.

Requirements (web tier only):
    pip install paramiko

Usage:
    from remote.ssh_scanner import scan_remote_linux
    result = scan_remote_linux("192.168.1.10", "admin", password="pass123")
"""

import json

# Graceful import — Paramiko is an optional web-tier dependency
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


# Inline scan script sent to the remote host.
# This is a condensed version that runs only the checks available via
# standard shell commands (no file upload of full module tree required).
_REMOTE_SCAN_SCRIPT = r'''
import subprocess, os, json, stat, glob, re, platform

def r(cmd, shell=False):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                       text=True, encoding="utf-8", errors="replace", shell=shell, timeout=15).strip()
    except Exception:
        return ""

findings = []

def add(category, type_, severity, description, mitigation, details=None):
    findings.append({"category": category, "type": type_, "severity": severity,
                     "description": description, "mitigation": mitigation,
                     "details": details or {}})

# ── System info ──────────────────────────────────────────────────────────────
hostname = r(["hostname"])
kernel   = r(["uname", "-r"])
user     = r(["whoami"])
os_name  = r(["cat", "/etc/os-release"], shell=False)

system_info = {
    "hostname": hostname, "kernel_release": kernel,
    "current_user": user, "os_name": os_name.split("\n")[0].replace("PRETTY_NAME=","").strip('"'),
    "is_root": (user == "root"),
}

# ── SUID/SGID binaries ───────────────────────────────────────────────────────
suid_raw = r("find / -perm /4000 -type f 2>/dev/null", shell=True)
GTFO = {"find","vim","vi","nano","less","more","man","awk","nmap","perl","python","python3",
        "ruby","lua","env","tee","cp","mv","bash","sh","dash","tcpdump","gdb","strace",
        "tar","zip","unzip","curl","wget","rsync","git","base64","xxd","screen","tmux"}
for path in suid_raw.splitlines():
    name = os.path.basename(path)
    if name in GTFO:
        add("SUID/SGID Binary", "SUID Binary with GTFOBins Exploit", "HIGH",
            f"SUID binary with GTFOBins exploit path: {path}",
            f"Remove SUID bit: chmod u-s {path}", {"path": path, "in_gtfobins": True})
    else:
        add("SUID/SGID Binary", "SUID Binary", "MEDIUM",
            f"SUID binary found: {path}",
            f"Review if SUID is required: chmod u-s {path}", {"path": path})

# ── Critical file permissions ────────────────────────────────────────────────
for f, expected_mode, severity in [
    ("/etc/shadow",  0o640, "CRITICAL"),
    ("/etc/passwd",  0o644, "MEDIUM"),
    ("/etc/sudoers", 0o440, "HIGH"),
]:
    if not os.path.exists(f): continue
    mode = oct(os.stat(f).st_mode & 0o777)
    if os.access(f, os.R_OK):
        add("File Permissions", f"{f} Readable by Current User", severity,
            f"{f} is readable by {user}. Mode: {mode}",
            f"Restrict permissions: chmod {oct(expected_mode)[2:]} {f}",
            {"file": f, "current_mode": mode})

# ── Sudo NOPASSWD ────────────────────────────────────────────────────────────
sudo_raw = r(["sudo", "-l"])
for line in sudo_raw.splitlines():
    if "NOPASSWD" in line:
        add("Services & Sudo", "Sudo NOPASSWD Rule", "HIGH",
            f"NOPASSWD sudo rule found: {line.strip()}",
            "Remove NOPASSWD from /etc/sudoers for this rule",
            {"sudo_rule": line.strip()})

# ── PATH hijacking ───────────────────────────────────────────────────────────
path_env = os.environ.get("PATH", "")
for d in path_env.split(":"):
    d = d.strip()
    if not d: continue
    if d in (".", ""):
        add("PATH Hijacking", "Dot or Empty in PATH", "HIGH",
            f"PATH contains '.' or empty entry — current directory searched for executables.",
            "Remove '.' from PATH in .bashrc/.profile", {"path_entry": d})
    elif os.path.isdir(d) and os.access(d, os.W_OK):
        add("PATH Hijacking", "Writable Directory in PATH", "MEDIUM",
            f"PATH directory '{d}' is writable by {user}.",
            f"Remove write permissions: chmod o-w {d}", {"directory": d})

# ── Kernel info for CVE matching (just report the version) ───────────────────
add("Kernel Info", "Kernel Version", "LOW",
    f"Running kernel: {kernel}. Verify against CVE database locally.",
    "Keep kernel updated: apt upgrade / yum update",
    {"kernel_release": kernel})

# ── World-writable /tmp or sensitive dirs ────────────────────────────────────
for d in ["/tmp", "/var/tmp", "/dev/shm"]:
    if os.path.isdir(d) and (os.stat(d).st_mode & 0o1000 == 0):
        add("File Permissions", "Sticky Bit Missing on Temp Directory", "MEDIUM",
            f"Temp directory {d} is missing the sticky bit.",
            f"Set sticky bit: chmod +t {d}", {"directory": d})

print(json.dumps({"system_info": system_info, "findings": findings}, indent=2))
'''


class RemoteScanError(Exception):
    pass


def scan_remote_linux(
    host: str,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    timeout: int = 30,
    verbose: bool = False,
) -> dict:
    """
    Perform an agentless privilege escalation scan on a remote Linux host via SSH.

    Args:
        host:      Target hostname or IP address
        username:  SSH username
        password:  SSH password (mutually exclusive with key_path)
        key_path:  Path to a PEM private key file
        port:      SSH port (default 22)
        timeout:   Connection timeout in seconds
        verbose:   Print progress messages

    Returns:
        dict with 'system_info' and 'findings' keys

    Raises:
        RemoteScanError: if the connection or scan fails
        ImportError:     if Paramiko is not installed
    """
    if not PARAMIKO_AVAILABLE:
        raise ImportError(
            "Paramiko is required for remote scanning. "
            "Install it: pip install paramiko"
        )

    if verbose:
        print(f"[*] Connecting to {username}@{host}:{port} via SSH...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if key_path:
            connect_kwargs["pkey"] = paramiko.RSAKey.from_private_key_file(key_path)
        elif password:
            connect_kwargs["password"] = password
        else:
            raise RemoteScanError("Either password or key_path must be provided.")

        client.connect(**connect_kwargs)

        if verbose:
            print("    Connected. Uploading scan script...")

        # Write the scan script to a temp file on the remote host
        stdin, stdout, stderr = client.exec_command(
            "python3 -c " + json.dumps(_REMOTE_SCAN_SCRIPT),
            timeout=120,
        )

        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")

        if verbose and err:
            print(f"    Remote stderr: {err[:200]}")

        # Find JSON in output (scan script prints JSON to stdout)
        json_start = out.find("{")
        if json_start == -1:
            raise RemoteScanError(
                f"No JSON output from remote scan. stderr: {err[:200]}"
            )

        result = json.loads(out[json_start:])

        if verbose:
            findings_count = len(result.get("findings", []))
            print(f"    Scan complete. {findings_count} finding(s) returned.")

        return result

    except paramiko.AuthenticationException as e:
        raise RemoteScanError(f"SSH authentication failed for {username}@{host}: {e}")
    except paramiko.SSHException as e:
        raise RemoteScanError(f"SSH error connecting to {host}: {e}")
    except json.JSONDecodeError as e:
        raise RemoteScanError(f"Failed to parse scan output from {host}: {e}")
    finally:
        client.close()
