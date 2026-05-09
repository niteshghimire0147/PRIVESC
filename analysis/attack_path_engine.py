"""
attack_path_engine.py — Attack Path Chaining Engine.

Chains individual findings into multi-step escalation paths.
Uses pure Python graph logic (no external dependencies).

Example chain:
    Writable cron script  +  Cron runs as root
    ──────────────────────────────────────────
    → GUARANTEED privilege escalation path

Returns:
    list of AttackPath objects, sorted by confidence/severity
"""

from __future__ import annotations


# ── Chain Rule Database ───────────────────────────────────────────────────────
# Each rule defines: conditions (list of finding matchers that must ALL be present)
# + the resulting path name, severity, and description.
#
# A matcher is a dict with optional keys: category, type, severity — all matched
# as case-insensitive substrings.

CHAIN_RULES: list[dict] = [

    # ── Linux Chains ───────────────────────────────────────────────────────────

    {
        "id": "LP-001",
        "name": "Writable Root Cron Script",
        "description": (
            "A cron job running as root references a script that the current user can write to. "
            "Overwriting this script with arbitrary commands guarantees code execution as root."
        ),
        "platform": "linux",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "conditions": [
            {"category": "cron", "type": "writable"},
        ],
        "mitre": "T1053.003",
        "steps": [
            "Identify the writable cron script path from the finding",
            "Append a reverse shell or SUID copy command to the script",
            "Wait for the cron job to execute",
            "Receive root shell or run the SUID binary",
        ],
    },

    {
        "id": "LP-002",
        "name": "GTFOBins SUID + No ASLR",
        "description": (
            "An exploitable SUID binary (in GTFOBins) is present and the kernel has ASLR disabled. "
            "The SUID binary can be used directly to obtain a root shell; ASLR absence removes a "
            "layer of exploitation difficulty for additional memory corruption bugs."
        ),
        "platform": "linux",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "conditions": [
            {"category": "suid", "type": "gtfobins"},
            {"type": "aslr"},
        ],
        "mitre": "T1548.001",
        "steps": [
            "Locate the SUID binary identified in the SUID finding",
            "Run the GTFOBins exploit command (included in finding details)",
            "Obtain root shell",
        ],
    },

    {
        "id": "LP-003",
        "name": "Sudo NOPASSWD + GTFOBins Command",
        "description": (
            "The current user has a NOPASSWD sudo rule for a command listed in GTFOBins. "
            "This is a direct, reliable escalation path requiring no further prerequisites."
        ),
        "platform": "linux",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "conditions": [
            {"category": "service", "type": "nopasswd"},
        ],
        "mitre": "T1548.003",
        "steps": [
            "Review sudo -l output to identify the NOPASSWD command",
            "Run the GTFOBins shell escape for that command via sudo",
            "Obtain root shell",
        ],
    },

    {
        "id": "LP-004",
        "name": "Writable PATH Dir + SUID Binary Uses Relative Path",
        "description": (
            "A directory in $PATH is writable by the current user, and a SUID binary "
            "calls a program using a relative (not absolute) path. Planting a malicious "
            "script with the expected name in the writable directory will execute it as root."
        ),
        "platform": "linux",
        "severity": "HIGH",
        "confidence": 0.80,
        "conditions": [
            {"category": "suid"},
            {"category": "path", "type": "writable"},
        ],
        "mitre": "T1574.007",
        "steps": [
            "Identify the writable PATH directory",
            "Create a malicious script with the name of a command called by the SUID binary",
            "Run the SUID binary to trigger PATH hijacking",
        ],
    },

    {
        "id": "LP-005",
        "name": "Exposed Shell History Credential + Sudo Access",
        "description": (
            "Shell history contains a credential or password, and the account with sudo access "
            "may reuse passwords. The credential in history could be tried against sudo or su."
        ),
        "platform": "linux",
        "severity": "HIGH",
        "confidence": 0.65,
        "conditions": [
            {"category": "credential"},
            {"category": "service", "type": "sudo"},
        ],
        "mitre": "T1552.003",
        "steps": [
            "Extract the credential from shell history",
            "Attempt sudo -s or su - with the discovered password",
        ],
    },

    {
        "id": "LP-006",
        "name": "Kernel CVE + Non-Root User",
        "description": (
            "The running kernel version matches a known local privilege escalation CVE "
            "and the current user is non-root. The CVE can be exploited to obtain root."
        ),
        "platform": "linux",
        "severity": "CRITICAL",
        "confidence": 0.90,
        "conditions": [
            {"category": "kernel", "type": "cve"},
        ],
        "mitre": "T1068",
        "steps": [
            "Compile or download the PoC exploit for the matched CVE",
            "Execute the exploit binary on the target",
            "Obtain root shell",
        ],
    },

    {
        "id": "LP-007",
        "name": "Dangerous Capability + GTFOBins Binary",
        "description": (
            "A binary with a dangerous Linux capability (cap_setuid, cap_sys_admin, etc.) "
            "is cross-referenced in GTFOBins. This allows escalating to UID 0 without SUID."
        ),
        "platform": "linux",
        "severity": "HIGH",
        "confidence": 0.92,
        "conditions": [
            {"category": "capabilities"},
        ],
        "mitre": "T1548.001",
        "steps": [
            "Identify the binary with the dangerous capability",
            "Run the GTFOBins capability exploit command",
            "Obtain root shell or read protected files",
        ],
    },

    # ── Windows Chains ─────────────────────────────────────────────────────────

    {
        "id": "WP-001",
        "name": "Writable Service Binary (SYSTEM Service)",
        "description": (
            "A Windows service running as SYSTEM or LocalSystem has a binary writable by the "
            "current user. Replacing the binary and restarting the service executes arbitrary "
            "code as SYSTEM."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.97,
        "conditions": [
            {"category": "windows service", "type": "writable"},
        ],
        "mitre": "T1574.005",
        "steps": [
            "Identify the writable service binary path",
            "Replace the binary with a payload (e.g., reverse shell)",
            "Restart the service: sc stop <svc> && sc start <svc>",
            "Receive SYSTEM shell",
        ],
    },

    {
        "id": "WP-002",
        "name": "Unquoted Service Path + Writable Intermediate Directory",
        "description": (
            "A service has an unquoted path with spaces and the current user can write to an "
            "intermediate directory. Planting an executable at the interception path will be "
            "executed as SYSTEM when the service starts."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "conditions": [
            {"category": "windows service", "type": "unquoted"},
        ],
        "mitre": "T1574.009",
        "steps": [
            "Identify the unquoted service path and writable intermediate directory",
            "Plant a payload EXE at the interception path",
            "Restart the service or wait for reboot",
            "Receive SYSTEM shell",
        ],
    },

    {
        "id": "WP-003",
        "name": "AlwaysInstallElevated + MSI Payload",
        "description": (
            "AlwaysInstallElevated is enabled. Any user can create and install an MSI package "
            "that runs as SYSTEM, providing a trivial and reliable escalation path."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "conditions": [
            {"category": "windows registry", "type": "alwaysinstallelevated"},
        ],
        "mitre": "T1548.002",
        "steps": [
            "Generate a malicious MSI: msfvenom -p windows/x64/shell_reverse_tcp -f msi -o privesc.msi",
            "Run: msiexec /quiet /qn /i privesc.msi",
            "Receive SYSTEM shell",
        ],
    },

    {
        "id": "WP-004",
        "name": "SeImpersonatePrivilege + Token Impersonation",
        "description": (
            "The current token has SeImpersonatePrivilege (or SeAssignPrimaryToken). "
            "Tools like PrintSpoofer or JuicyPotatoNG can leverage this to obtain a SYSTEM token "
            "via named pipe impersonation or COM activation."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "conditions": [
            {"category": "token", "type": "seimpersonateprivilege"},
        ],
        "mitre": "T1134.001",
        "steps": [
            "Confirm SeImpersonatePrivilege is Enabled (whoami /priv)",
            "Run: PrintSpoofer64.exe -i -c cmd.exe",
            "Obtain SYSTEM shell",
        ],
    },

    {
        "id": "WP-005",
        "name": "Autologon Password + Admin Account",
        "description": (
            "A plaintext autologon password is stored in the registry. If this password "
            "belongs to an administrator account, it provides direct privileged access."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.88,
        "conditions": [
            {"category": "windows registry", "type": "autologon"},
        ],
        "mitre": "T1552.002",
        "steps": [
            "Extract the autologon credentials from HKLM\\...\\Winlogon",
            "Use the credentials: runas /user:<username> cmd.exe",
            "Or authenticate via RDP, WMI, or PsExec",
        ],
    },

    {
        "id": "WP-006",
        "name": "Kernel CVE + Standard User",
        "description": (
            "The Windows OS version matches a known local privilege escalation CVE "
            "and the current user is not elevated. The CVE can be exploited to obtain SYSTEM."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.90,
        "conditions": [
            {"category": "windows kernel", "type": "cve"},
        ],
        "mitre": "T1068",
        "steps": [
            "Identify the matched CVE and its public PoC",
            "Compile or download the exploit",
            "Execute and obtain SYSTEM shell",
        ],
    },

    {
        "id": "WP-007",
        "name": "UAC Disabled + Admin Group Membership",
        "description": (
            "UAC is fully disabled and the current user is a member of the Administrators group. "
            "All processes run with full admin rights — no further escalation technique required."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "conditions": [
            {"category": "windows uac", "type": "disabled"},
        ],
        "mitre": "T1548.002",
        "steps": [
            "Confirm UAC is disabled (EnableLUA = 0)",
            "Launch any administrative operation directly — no elevation prompt will appear",
        ],
    },

    {
        "id": "WP-008",
        "name": "cmdkey Stored Credential + runas /savecred",
        "description": (
            "Windows Credential Manager has stored credentials. If they belong to an admin "
            "account, runas /savecred can execute commands as that account without re-prompting."
        ),
        "platform": "windows",
        "severity": "HIGH",
        "confidence": 0.82,
        "conditions": [
            {"category": "windows credentials", "type": "cmdkey"},
        ],
        "mitre": "T1552.004",
        "steps": [
            "List stored credentials: cmdkey /list",
            "Use stored credential: runas /savecred /user:<username> cmd.exe",
        ],
    },

    {
        "id": "WP-009",
        "name": "Writable Scheduled Task + SYSTEM Runner",
        "description": (
            "A SYSTEM-level scheduled task references an executable that the current user can "
            "overwrite. Replacing the binary and waiting for the scheduled trigger executes "
            "arbitrary code as SYSTEM."
        ),
        "platform": "windows",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "conditions": [
            {"category": "windows scheduled task", "type": "writable"},
        ],
        "mitre": "T1053.005",
        "steps": [
            "Identify the writable task executable",
            "Replace it with a payload",
            "Wait for the scheduled task trigger",
            "Receive SYSTEM shell",
        ],
    },
]


# ── AttackPath Data Class ─────────────────────────────────────────────────────

class AttackPath:
    def __init__(self, rule: dict, matched_findings: list[dict]):
        self.id               = rule["id"]
        self.name             = rule["name"]
        self.description      = rule["description"]
        self.platform         = rule["platform"]
        self.severity         = rule["severity"]
        self.confidence       = rule["confidence"]
        self.mitre            = rule.get("mitre", "")
        self.steps            = rule.get("steps", [])
        self.matched_findings = matched_findings

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "name":             self.name,
            "description":      self.description,
            "platform":         self.platform,
            "severity":         self.severity,
            "confidence":       self.confidence,
            "confidence_pct":   f"{self.confidence * 100:.0f}%",
            "mitre_attack":     self.mitre,
            "steps":            self.steps,
            "matched_findings": [
                {
                    "category": f.get("category"),
                    "type":     f.get("type"),
                    "severity": f.get("severity"),
                }
                for f in self.matched_findings
            ],
        }


# ── Engine ────────────────────────────────────────────────────────────────────

def _matches_condition(finding: dict, condition: dict) -> bool:
    """Return True if a finding satisfies a condition matcher."""
    f_cat  = finding.get("category", "").lower()
    f_type = finding.get("type", "").lower()
    f_desc = finding.get("description", "").lower()
    f_sev  = finding.get("severity", "").lower()

    if "category" in condition:
        pat = condition["category"].lower()
        if pat not in f_cat and pat not in f_desc:
            return False
    if "type" in condition:
        pat = condition["type"].lower()
        if pat not in f_type and pat not in f_desc and pat not in f_cat:
            return False
    if "severity" in condition:
        if condition["severity"].lower() != f_sev:
            return False
    return True


def analyse_attack_paths(findings: list[dict]) -> list[AttackPath]:
    """
    Analyse a list of findings and return detected attack paths, sorted by
    severity then confidence (descending).

    Args:
        findings: list of finding dicts from scanner modules

    Returns:
        list of AttackPath objects
    """
    paths: list[AttackPath] = []

    for rule in CHAIN_RULES:
        matched_per_condition: list[list[dict]] = []

        for condition in rule["conditions"]:
            matches = [f for f in findings if _matches_condition(f, condition)]
            matched_per_condition.append(matches)

        # All conditions must be satisfied by at least one finding
        if all(len(m) > 0 for m in matched_per_condition):
            # Flatten unique matched findings
            all_matched: list[dict] = []
            seen_keys: set = set()
            for matches in matched_per_condition:
                for f in matches:
                    key = (f.get("category"), f.get("type"), f.get("description", "")[:50])
                    if key not in seen_keys:
                        all_matched.append(f)
                        seen_keys.add(key)

            paths.append(AttackPath(rule, all_matched))

    # Sort: CRITICAL first, then by confidence desc
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    paths.sort(key=lambda p: (sev_order.get(p.severity, 9), -p.confidence))

    return paths
