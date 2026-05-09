"""
suid_scanner.py — Step 2a: SUID/SGID binary discovery.

Scans the filesystem for binaries with SUID or SGID bits set,
then cross-references against the GTFOBins database to identify
those with known exploitation paths.
"""

import subprocess
import os
import json


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


def _load_gtfobins(data_dir):
    """Load the GTFOBins database from data/gtfobins.json."""
    gtfobins_path = os.path.join(data_dir, "gtfobins.json")
    try:
        with open(gtfobins_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# Common SUID binary locations for quick mode (avoids full filesystem walk)
QUICK_SCAN_PATHS = [
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/opt", "/snap/bin",
]


def scan(data_dir=None, verbose=False, quick=False):
    """
    Scan for SUID and SGID binaries and check against GTFOBins.

    Args:
        data_dir (str): Path to the data/ directory containing gtfobins.json.
        verbose (bool): Print progress messages.
        quick (bool): If True, only scan common binary directories instead of
                      the full filesystem (much faster).

    Returns:
        list[dict]: Findings, each containing:
            path, binary_name, bit_type, in_gtfobins,
            severity, exploit_notes, category, mitigation
    """
    if data_dir is None:
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

    gtfobins = _load_gtfobins(data_dir)
    findings = []

    # --- SUID binaries (Set User ID) ---
    if verbose:
        print("[*] Scanning for SUID binaries...")

    if quick:
        paths_arg = " ".join(p for p in QUICK_SCAN_PATHS if os.path.isdir(p))
        suid_cmd = f"find {paths_arg} -perm -4000 -type f 2>/dev/null" if paths_arg else ""
    else:
        suid_cmd = "find / -perm -4000 -type f 2>/dev/null"

    suid_paths = _run(suid_cmd) if suid_cmd else []

    for path in suid_paths:
        binary_name = os.path.basename(path).lower()
        # Strip version suffixes like python3.8 → python3
        name_key = binary_name.rstrip("0123456789.")
        gtfo_match = gtfobins.get(binary_name) or gtfobins.get(name_key)

        if gtfo_match:
            severity = "HIGH"
            ftype = "SUID Binary with GTFOBins Exploit"
            notes = gtfo_match.get("notes", "")
            exploit = gtfo_match.get("exploit", "")
        else:
            severity = "LOW"
            ftype = "SUID Binary"
            notes = "Binary has SUID bit but no known GTFOBins exploit path."
            exploit = ""

        findings.append({
            "category": "SUID/SGID Binary",
            "type": ftype,
            "path": path,
            "binary_name": binary_name,
            "bit_type": "SUID",
            "in_gtfobins": bool(gtfo_match),
            "severity": severity,
            "notes": notes,
            "exploit_example": exploit,
            "mitigation": (
                f"Remove SUID bit if not required: chmod u-s {path}\n"
                "  Audit whether this binary needs elevated privileges for its function."
            ),
        })

    # --- SGID binaries (Set Group ID) ---
    if verbose:
        print("[*] Scanning for SGID binaries...")

    if quick:
        sgid_cmd = f"find {paths_arg} -perm -2000 -type f 2>/dev/null" if paths_arg else ""
    else:
        sgid_cmd = "find / -perm -2000 -type f 2>/dev/null"

    sgid_paths = _run(sgid_cmd) if sgid_cmd else []

    for path in sgid_paths:
        binary_name = os.path.basename(path).lower()
        name_key = binary_name.rstrip("0123456789.")
        gtfo_match = gtfobins.get(binary_name) or gtfobins.get(name_key)

        # Skip common safe SGID binaries (mail, ssh-agent, crontab)
        safe_sgid = {"wall", "write", "ssh-agent", "crontab", "at", "mlocate",
                     "lockfile", "dotlockfile", "expiry", "chage", "newgrp"}
        if binary_name in safe_sgid and not gtfo_match:
            severity = "LOW"
        elif gtfo_match:
            severity = "HIGH"
        else:
            severity = "LOW"

        if gtfo_match:
            sgid_type = "SGID Binary with GTFOBins Exploit"
            notes = gtfo_match.get("notes", "Binary has SGID bit set.")
            exploit = gtfo_match.get("exploit", "")
        else:
            sgid_type = "SGID Binary"
            notes = "Binary has SGID bit set."
            exploit = ""

        findings.append({
            "category": "SUID/SGID Binary",
            "type": sgid_type,
            "path": path,
            "binary_name": binary_name,
            "bit_type": "SGID",
            "in_gtfobins": bool(gtfo_match),
            "severity": severity,
            "notes": notes,
            "exploit_example": exploit,
            "mitigation": (
                f"Remove SGID bit if not required: chmod g-s {path}\n"
                "  Verify the binary needs group-level access for its function."
            ),
        })

    if verbose:
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        print(f"[+] SUID/SGID scan complete: {len(findings)} binaries found, {high} with GTFOBins exploit paths.")

    return findings
