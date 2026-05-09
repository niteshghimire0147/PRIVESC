"""
service_scanner.py — Step 2c: Misconfigured services and sudo rules.

Checks:
  1. Systemd service files with writable ExecStart binaries
  2. Services running as root with user-writable paths
  3. sudo -l misconfigurations (NOPASSWD, wildcards, dangerous commands)
  4. Dangerous PATH entries in service files
"""

import subprocess
import os
import re
import stat


def _run(cmd):
    """Run a shell command and return stdout lines."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        output = result.stdout.decode("utf-8", errors="replace").strip()
        return [line.strip() for line in output.splitlines() if line.strip()]
    except Exception:
        return []


def _run_raw(cmd):
    """Run a command and return the full raw output as a string."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        return result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _is_writable_by_others(path):
    """Check if a file is writable by non-root users."""
    try:
        st = os.stat(path)
        # World-writable or group-writable (rough check)
        return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    except Exception:
        return False


def _is_world_writable(path):
    """Check if a file is world-writable."""
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IWOTH)
    except Exception:
        return False


def _scan_systemd_services(verbose=False):
    """Scan enabled systemd service files for misconfigurations."""
    findings = []
    if verbose:
        print("[*] Scanning systemd service files...")

    service_dirs = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ]

    all_service_files = []
    for d in service_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                if fname.endswith(".service"):
                    all_service_files.append(os.path.join(d, fname))
        except OSError:
            pass

    for service_file in all_service_files:
        try:
            with open(service_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue

        service_name = os.path.basename(service_file)
        exec_starts = re.findall(r"^ExecStart\s*=\s*(.+)$", content, re.MULTILINE)
        user_field = re.search(r"^User\s*=\s*(.+)$", content, re.MULTILINE)
        env_fields = re.findall(r"^Environment\s*=\s*(.+)$", content, re.MULTILINE)

        run_as_root = (user_field is None) or (user_field.group(1).strip() in ("root", "0"))

        for exec_line in exec_starts:
            # Extract the actual binary path (strip arguments and @ prefixes)
            exec_line = exec_line.strip().lstrip("-@+!")
            binary_path = exec_line.split()[0] if exec_line.split() else ""

            if not binary_path or not os.path.isabs(binary_path):
                continue

            if not os.path.exists(binary_path):
                # Binary referenced but does not exist — potential hijack
                if run_as_root:
                    findings.append({
                        "category": "Misconfigured Service",
                        "type": "Missing Service Binary",
                        "service": service_name,
                        "service_file": service_file,
                        "binary_path": binary_path,
                        "runs_as": "root" if run_as_root else (user_field.group(1).strip() if user_field else "unknown"),
                        "severity": "HIGH",
                        "notes": (
                            f"Service {service_name} references binary {binary_path} "
                            "which does not exist. An attacker could create this file to gain code execution as root."
                        ),
                        "mitigation": (
                            f"Create the missing binary at {binary_path} with correct permissions,\n"
                            "  OR disable the service: systemctl disable " + service_name.replace(".service", "")
                        ),
                    })
                continue

            if run_as_root and _is_writable_by_others(binary_path):
                severity = "CRITICAL" if _is_world_writable(binary_path) else "HIGH"
                findings.append({
                    "category": "Misconfigured Service",
                    "type": "Writable Service Binary",
                    "service": service_name,
                    "service_file": service_file,
                    "binary_path": binary_path,
                    "runs_as": "root",
                    "severity": severity,
                    "notes": (
                        f"Service {service_name} runs as root and its binary {binary_path} "
                        "is writable by non-root users. An attacker can replace the binary to escalate privileges."
                    ),
                    "mitigation": (
                        f"Restrict write access: chmod o-w {binary_path}\n"
                        f"  Verify ownership: chown root:root {binary_path}"
                    ),
                })

        # Check for dangerous PATH in Environment=
        for env_line in env_fields:
            if "PATH=" in env_line:
                path_val = env_line.split("PATH=", 1)[1].split()[0]
                path_dirs = path_val.split(":")
                dangerous_paths = []
                for p in path_dirs:
                    if p in (".", "", "/tmp", "/var/tmp") or _is_world_writable(p):
                        dangerous_paths.append(p)
                if dangerous_paths:
                    findings.append({
                        "category": "Misconfigured Service",
                        "type": "Dangerous PATH in Service",
                        "service": service_name,
                        "service_file": service_file,
                        "binary_path": "N/A",
                        "runs_as": "root" if run_as_root else "non-root",
                        "severity": "HIGH" if run_as_root else "MEDIUM",
                        "notes": (
                            f"Service {service_name} sets PATH={path_val} which includes "
                            f"world-writable or dangerous directories: {dangerous_paths}. "
                            "This can enable PATH hijacking attacks."
                        ),
                        "mitigation": (
                            f"Remove dangerous entries from PATH in {service_file}.\n"
                            "  Use absolute paths for all commands in service files."
                        ),
                    })

    return findings


# Commands that are commonly exploited via sudo
DANGEROUS_SUDO_CMDS = {
    "ALL", "find", "vim", "vi", "nano", "less", "more", "awk", "perl",
    "python", "python2", "python3", "ruby", "lua", "php", "bash", "sh", "dash",
    "env", "tar", "zip", "unzip", "socat", "nc", "netcat", "nmap", "wget", "curl",
    "docker", "kubectl", "git", "make", "tee", "cp", "mv", "chmod", "chown",
    "cat", "head", "tail", "sed", "dd", "rsync", "screen", "tmux",
    "strace", "ltrace", "node", "npm", "pip", "pip3", "apt", "apt-get", "yum",
    "dnf", "pacman", "dpkg", "rpm", "mount", "umount", "ftp", "sftp", "scp",
}


def _scan_sudo(verbose=False):
    """Parse sudo -l output for dangerous configurations."""
    findings = []
    if verbose:
        print("[*] Checking sudo configuration (sudo -l)...")

    sudo_output = _run_raw("sudo -l 2>/dev/null")
    if not sudo_output.strip():
        if verbose:
            print("    [!] Could not run sudo -l (may need a password or sudo is not available).")
        return findings

    lines = sudo_output.splitlines()

    for line in lines:
        line = line.strip()

        # NOPASSWD rule
        if "NOPASSWD" in line and "(" in line:
            # Extract the command(s) after NOPASSWD:
            commands_part = line.split("NOPASSWD:", 1)[-1].strip() if "NOPASSWD:" in line else line
            commands = [c.strip() for c in commands_part.split(",")]

            for cmd in commands:
                cmd_binary = os.path.basename(cmd.split()[0]) if cmd.split() else ""
                is_dangerous = (
                    cmd_binary.upper() == "ALL" or
                    cmd_binary in DANGEROUS_SUDO_CMDS or
                    cmd == "ALL"
                )

                severity = "CRITICAL" if (cmd == "ALL" or "(ALL)" in line) else ("HIGH" if is_dangerous else "MEDIUM")

                findings.append({
                    "category": "Misconfigured Service",
                    "type": "Sudo NOPASSWD Rule",
                    "service": "sudo",
                    "service_file": "/etc/sudoers",
                    "binary_path": cmd,
                    "runs_as": "root",
                    "severity": severity,
                    "notes": (
                        f"Sudo rule allows running '{cmd}' as root WITHOUT a password.\n"
                        "    Raw rule: " + line
                    ),
                    "mitigation": (
                        "Remove NOPASSWD from the sudo rule or restrict to safe, specific commands.\n"
                        "  Edit with: sudo visudo"
                    ),
                })

        # ALL=(ALL) ALL — full sudo access
        elif re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", line):
            findings.append({
                "category": "Misconfigured Service",
                "type": "Full Sudo Access",
                "service": "sudo",
                "service_file": "/etc/sudoers",
                "binary_path": "ALL",
                "runs_as": "root",
                "severity": "HIGH",
                "notes": (
                    "User has full sudo access (ALL commands as root). "
                    "This is a legitimate admin configuration but represents a high-privilege account.\n"
                    "    Raw rule: " + line
                ),
                "mitigation": (
                    "If this user does not need full root access, restrict to specific commands in /etc/sudoers."
                ),
            })

    return findings


def scan(verbose=False):
    """
    Run all service and sudo checks.

    Returns:
        list[dict]: All service-related findings.
    """
    findings = []
    findings.extend(_scan_systemd_services(verbose=verbose))
    findings.extend(_scan_sudo(verbose=verbose))

    if verbose:
        print(f"[+] Service scan complete: {len(findings)} findings.")

    return findings
