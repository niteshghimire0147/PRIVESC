"""
capabilities_scanner.py — Step 2f: Linux capabilities detection.

Linux capabilities partition root privileges into smaller units.
Certain capabilities assigned to binaries are as dangerous as SUID root.

Scans for:
  1. Binaries with dangerous capabilities set via 'getcap'
  2. Cross-references with GTFOBins for exploit paths
"""

import subprocess
import os
import json
import re


def _run(cmd):
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        return result.stdout.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _load_gtfobins(data_dir):
    """Load GTFOBins database."""
    gtfobins_path = os.path.join(data_dir, "gtfobins.json")
    try:
        with open(gtfobins_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


# Capabilities that are directly dangerous for privilege escalation
DANGEROUS_CAPS = {
    "cap_setuid": {
        "severity": "CRITICAL",
        "description": "Allows setting arbitrary UIDs. A binary with cap_setuid can call setuid(0) to become root.",
        "exploit": "Use the binary to call setuid(0) then exec /bin/sh",
    },
    "cap_setgid": {
        "severity": "CRITICAL",
        "description": "Allows setting arbitrary GIDs. Can be used to gain access to sensitive groups.",
        "exploit": "Use the binary to call setgid(0) to join root group",
    },
    "cap_dac_override": {
        "severity": "HIGH",
        "description": "Bypasses file read/write/execute permission checks. Allows reading /etc/shadow and writing to any file.",
        "exploit": "Read or overwrite any file on the system regardless of permissions",
    },
    "cap_dac_read_search": {
        "severity": "HIGH",
        "description": "Bypasses file read permission and directory read/execute checks.",
        "exploit": "Read any file on the system including /etc/shadow",
    },
    "cap_sys_admin": {
        "severity": "CRITICAL",
        "description": "A broad capability covering many privileged operations. Often described as 'the new root'.",
        "exploit": "Mount filesystems, manage namespaces, or use many other privileged operations",
    },
    "cap_sys_ptrace": {
        "severity": "HIGH",
        "description": "Allows tracing arbitrary processes. Can be used to inject code into running processes.",
        "exploit": "Attach to a root process via ptrace and inject shellcode",
    },
    "cap_net_raw": {
        "severity": "MEDIUM",
        "description": "Allows creating raw sockets and packet injection.",
        "exploit": "Intercept network traffic or perform network-based attacks",
    },
    "cap_net_bind_service": {
        "severity": "LOW",
        "description": "Allows binding to ports below 1024 without root.",
        "exploit": "Bind to privileged ports (e.g., 80, 443) — limited direct privesc use",
    },
    "cap_sys_rawio": {
        "severity": "HIGH",
        "description": "Allows direct hardware access. Can read from raw disk devices.",
        "exploit": "Read raw disk data bypassing filesystem permissions",
    },
    "cap_chown": {
        "severity": "HIGH",
        "description": "Allows changing file ownership arbitrarily.",
        "exploit": "Chown a sensitive file to the current user, then read/modify it",
    },
    "cap_fowner": {
        "severity": "HIGH",
        "description": "Bypass permission checks for operations requiring file owner.",
        "exploit": "Modify permissions of any file without being its owner",
    },
    "cap_sys_module": {
        "severity": "CRITICAL",
        "description": "Allows loading and unloading kernel modules.",
        "exploit": "Load a malicious kernel module to gain full kernel code execution",
    },
    "cap_kill": {
        "severity": "LOW",
        "description": "Allows sending signals to any process.",
        "exploit": "Kill security-critical processes (limited direct privesc use)",
    },
}


def scan(data_dir=None, verbose=False):
    """
    Scan for binaries with dangerous Linux capabilities.

    Args:
        data_dir (str): Path to the data/ directory.
        verbose (bool): Print progress messages.

    Returns:
        list[dict]: Capability-related findings.
    """
    if data_dir is None:
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

    gtfobins = _load_gtfobins(data_dir)
    findings = []

    if verbose:
        print("[*] Scanning for Linux capabilities (getcap)...")

    raw = _run("getcap -r / 2>/dev/null")
    if not raw:
        if verbose:
            print("    [!] 'getcap' not found or returned no results.")
        return findings

    # Parse output: each line is like "/usr/bin/python3.8 = cap_net_raw+e"
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue

        # Split on " = " to separate path from capabilities
        parts = line.split(" = ", 1)
        if len(parts) != 2:
            continue

        binary_path = parts[0].strip()
        caps_string = parts[1].strip()

        # Parse capability names (strip +eip suffixes)
        # e.g. "cap_net_raw+ep" → "cap_net_raw"
        cap_names = re.findall(r"(cap_[a-z_]+)", caps_string.lower())

        if not cap_names:
            continue

        # Check against dangerous capabilities list
        matched_dangerous = []
        highest_severity = "LOW"
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for cap in cap_names:
            if cap in DANGEROUS_CAPS:
                cap_info = DANGEROUS_CAPS[cap]
                matched_dangerous.append({
                    "cap": cap,
                    "severity": cap_info["severity"],
                    "description": cap_info["description"],
                    "exploit": cap_info["exploit"],
                })
                if severity_order.get(cap_info["severity"], 0) > severity_order.get(highest_severity, 0):
                    highest_severity = cap_info["severity"]

        if not matched_dangerous:
            highest_severity = "LOW"

        # GTFOBins cross-reference
        binary_name = os.path.basename(binary_path).lower()
        name_key = binary_name.rstrip("0123456789.")
        gtfo_match = gtfobins.get(binary_name) or gtfobins.get(name_key)

        # Build description
        cap_descriptions = []
        for d in matched_dangerous:
            cap_descriptions.append(f"{d['cap']}: {d['description']}")

        if not cap_descriptions:
            cap_descriptions = [f"Has capabilities: {caps_string} (not flagged as directly dangerous)"]
            if not gtfo_match:
                highest_severity = "LOW"
            else:
                highest_severity = "MEDIUM"

        gtfo_notes = ""
        if gtfo_match:
            gtfo_notes = f"\n    GTFOBins: {gtfo_match.get('notes', '')} | Exploit: {gtfo_match.get('exploit', '')}"
            # Elevate severity if GTFOBins match
            if severity_order.get(highest_severity, 0) < severity_order.get("HIGH", 0):
                highest_severity = "HIGH"

        findings.append({
            "category": "Linux Capabilities",
            "type": "Dangerous Capability",
            "path": binary_path,
            "binary_name": binary_name,
            "capabilities": caps_string,
            "dangerous_caps": [d["cap"] for d in matched_dangerous],
            "in_gtfobins": bool(gtfo_match),
            "severity": highest_severity,
            "notes": (
                f"Binary {binary_path} has capabilities: {caps_string}\n"
                "    " + "\n    ".join(cap_descriptions) + gtfo_notes
            ),
            "mitigation": (
                f"Remove capabilities if not required: setcap -r {binary_path}\n"
                "  If capabilities are needed, prefer a wrapper service that drops them after use."
            ),
        })

    if verbose:
        print(f"[+] Capabilities scan complete: {len(findings)} findings.")

    return findings
