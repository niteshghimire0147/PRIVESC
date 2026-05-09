"""
kernel_scanner.py — Step 2e: Kernel version and CVE detection.

Checks:
  1. Running kernel version vs known CVE database
  2. End-of-life kernel detection
  3. Basic kernel hardening settings (ASLR, dmesg restrictions)
"""

import subprocess
import os
import json
import re


def _run(cmd):
    """Run a shell command and return stripped output."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        return result.stdout.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _parse_version(version_str):
    """
    Parse a kernel version string into comparable tuple.

    Examples:
        '5.4.0-147-generic' → (5, 4, 0)
        '4.15.0' → (4, 15, 0)
        '6.1.38-1-lts' → (6, 1, 38)
    """
    # Extract the first major.minor.patch numbers
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if match:
        return tuple(int(x) for x in match.groups())
    match = re.search(r"(\d+)\.(\d+)", version_str)
    if match:
        return (int(match.group(1)), int(match.group(2)), 0)
    return (0, 0, 0)


def _version_in_range(kernel_tuple, min_ver_str=None, max_ver_str=None):
    """
    Check if kernel_tuple falls within [min_ver_str, max_ver_str].
    'None' means no bound on that side.
    """
    if min_ver_str:
        min_tuple = _parse_version(min_ver_str)
        if kernel_tuple < min_tuple:
            return False
    if max_ver_str:
        max_tuple = _parse_version(max_ver_str)
        if kernel_tuple > max_tuple:
            return False
    return True


def _load_cve_db(data_dir):
    """Load kernel CVE database from data/kernel_cves.json."""
    cve_path = os.path.join(data_dir, "kernel_cves.json")
    try:
        with open(cve_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


# EOL kernel boundaries: kernels older than these are considered end-of-life
# Format: (major, minor) tuples — kernels with version < this are EOL
EOL_KERNEL_THRESHOLD = (5, 4)  # 5.4 is an LTS kernel; older = EOL for most distros


def _check_kernel_hardening(verbose=False):
    """Check basic kernel hardening settings via /proc/sys."""
    findings = []

    checks = [
        {
            "path": "/proc/sys/kernel/randomize_va_space",
            "expected": "2",
            "name": "ASLR (Address Space Layout Randomization)",
            "severity": "HIGH",
            "description": "ASLR randomizes memory layout to make exploitation harder.",
            "mitigation": "Enable full ASLR: echo 2 > /proc/sys/kernel/randomize_va_space\n  Persist: add 'kernel.randomize_va_space=2' to /etc/sysctl.conf",
        },
        {
            "path": "/proc/sys/kernel/dmesg_restrict",
            "expected": "1",
            "name": "dmesg restriction",
            "severity": "LOW",
            "description": "When set to 0, unprivileged users can read kernel messages which may leak addresses.",
            "mitigation": "Restrict dmesg: echo 1 > /proc/sys/kernel/dmesg_restrict\n  Persist: add 'kernel.dmesg_restrict=1' to /etc/sysctl.conf",
        },
        {
            "path": "/proc/sys/kernel/kptr_restrict",
            "expected": "2",
            "name": "Kernel pointer restriction (kptr_restrict)",
            "severity": "MEDIUM",
            "description": "When 0, kernel pointer values are exposed in /proc files, aiding exploit development.",
            "mitigation": "Restrict kernel pointers: echo 2 > /proc/sys/kernel/kptr_restrict\n  Persist: add 'kernel.kptr_restrict=2' to /etc/sysctl.conf",
        },
        {
            "path": "/proc/sys/kernel/perf_event_paranoid",
            "expected": "3",
            "name": "perf_event access restriction",
            "severity": "LOW",
            "description": "Low paranoia level allows unprivileged users to use perf_event system calls.",
            "mitigation": "Restrict perf events: echo 3 > /proc/sys/kernel/perf_event_paranoid\n  Persist: add 'kernel.perf_event_paranoid=3' to /etc/sysctl.conf",
        },
        {
            "path": "/proc/sys/fs/suid_dumpable",
            "expected": "0",
            "name": "SUID core dump restriction",
            "severity": "MEDIUM",
            "description": "When non-zero, SUID binaries can generate core dumps that may expose sensitive memory.",
            "mitigation": "Disable SUID dumps: echo 0 > /proc/sys/fs/suid_dumpable\n  Persist: add 'fs.suid_dumpable=0' to /etc/sysctl.conf",
        },
        {
            "path": "/proc/sys/kernel/yama/ptrace_scope",
            "expected": "1",
            "name": "ptrace scope restriction (Yama LSM)",
            "severity": "HIGH",
            "description": "ptrace scope 0 allows any process to ptrace any other process, enabling memory inspection and code injection.",
            "mitigation": "Restrict ptrace: echo 1 > /proc/sys/kernel/yama/ptrace_scope\n  Persist: add 'kernel.yama.ptrace_scope=1' to /etc/sysctl.conf",
        },
    ]

    for check in checks:
        try:
            with open(check["path"], "r", encoding="utf-8") as f:
                current = f.read().strip()
        except Exception:
            continue  # File doesn't exist on this kernel/config

        if current != check["expected"]:
            findings.append({
                "category": "Kernel Security",
                "type": "Weak Kernel Hardening",
                "cve_id": "N/A",
                "setting": check["path"],
                "current_value": current,
                "expected_value": check["expected"],
                "severity": check["severity"],
                "notes": (
                    f"{check['name']} is set to {current} (recommended: {check['expected']}). "
                    f"{check['description']}"
                ),
                "mitigation": check["mitigation"],
                "reference": "Linux kernel hardening documentation",
            })

    return findings


def scan(data_dir=None, verbose=False):
    """
    Check running kernel against known CVEs and hardening settings.

    Args:
        data_dir (str): Path to the data/ directory.
        verbose (bool): Print progress messages.

    Returns:
        list[dict]: Kernel-related findings.
    """
    if data_dir is None:
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

    findings = []

    if verbose:
        print("[*] Checking kernel version and CVEs...")

    kernel_release = _run("uname -r")
    kernel_tuple = _parse_version(kernel_release)

    if verbose:
        print(f"    Kernel: {kernel_release} → parsed as {kernel_tuple}")

    # Check for EOL kernel
    if kernel_tuple < EOL_KERNEL_THRESHOLD:
        findings.append({
            "category": "Kernel Security",
            "type": "End-of-Life Kernel",
            "cve_id": "N/A",
            "kernel_version": kernel_release,
            "severity": "HIGH",
            "notes": (
                f"Kernel {kernel_release} is older than {'.'.join(str(x) for x in EOL_KERNEL_THRESHOLD)} "
                "and may be End-of-Life with no upstream security patches. "
                "EOL kernels do not receive security updates and are vulnerable to all unpatched CVEs."
            ),
            "mitigation": (
                "Upgrade the kernel to a supported LTS version.\n"
                "  Check available kernels: apt-cache search linux-image (Debian/Ubuntu)\n"
                "  Install: sudo apt-get install linux-image-<version>"
            ),
            "reference": "https://www.kernel.org/category/releases.html",
        })

    # Match against CVE database
    cve_db = _load_cve_db(data_dir)
    for cve in cve_db:
        min_ver = cve.get("affected_kernel_min")
        max_ver = cve.get("affected_kernel_max")

        if _version_in_range(kernel_tuple, min_ver_str=min_ver, max_ver_str=max_ver):
            findings.append({
                "category": "Kernel Security",
                "type": "Known Kernel CVE",
                "cve_id": cve.get("cve_id", "Unknown"),
                "cve_name": cve.get("name", ""),
                "kernel_version": kernel_release,
                "severity": cve.get("severity", "MEDIUM"),
                "notes": (
                    f"{cve.get('cve_id')} ({cve.get('name', '')}): {cve.get('description', '')}\n"
                    f"    CVSS Score: {cve.get('cvss', 'N/A')} | Affected component: {cve.get('affected_component', 'N/A')}"
                ),
                "mitigation": cve.get("mitigation", "Update the kernel to a patched version."),
                "reference": cve.get("reference", ""),
            })

    # Check kernel hardening settings
    findings.extend(_check_kernel_hardening(verbose=verbose))

    if verbose:
        cve_count = sum(1 for f in findings if f.get("type") == "Known Kernel CVE")
        print(f"[+] Kernel scan complete: {cve_count} CVEs matched, {len(findings)} total findings.")

    return findings
