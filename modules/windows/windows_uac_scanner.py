"""
windows_uac_scanner.py — Detect UAC misconfigurations and bypass opportunities.

Checks:
  - UAC consent level (registry EnableLUA, ConsentPromptBehaviorAdmin)
  - UAC disabled entirely
  - Token elevation type (full vs. limited — indicates bypass opportunity)
  - Current user is in Administrators group but running as limited token
"""

import subprocess


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return r.stdout.strip()
    except Exception:
        return ""


def _run_powershell(script: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _query_reg_value(key_path: str, value_name: str) -> str | None:
    try:
        import winreg
        hive = winreg.HKEY_LOCAL_MACHINE
        with winreg.OpenKey(hive, key_path) as k:
            data, _ = winreg.QueryValueEx(k, value_name)
            return str(data)
    except Exception:
        return None


UAC_CONSENT_LEVELS = {
    "0": ("No consent prompt — UAC auto-elevates silently", "CRITICAL"),
    "1": ("Secure desktop with credentials prompt for non-Windows binaries", "LOW"),
    "2": ("Secure desktop with credentials prompt for all", "LOW"),
    "3": ("Consent prompt without secure desktop", "MEDIUM"),
    "4": ("Consent prompt only for non-Windows binaries", "LOW"),
    "5": ("Consent prompt for non-Windows binaries (default)", "LOW"),
}


def _check_uac_settings() -> list[dict]:
    """Check UAC registry settings for dangerous configurations."""
    findings = []
    uac_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    enable_lua = _query_reg_value(uac_key, "EnableLUA")
    consent_level = _query_reg_value(uac_key, "ConsentPromptBehaviorAdmin")
    admin_prompt_user = _query_reg_value(uac_key, "ConsentPromptBehaviorUser")
    local_admin_bypass = _query_reg_value(uac_key, "LocalAccountTokenFilterPolicy")

    # Auto-elevate standard users without consent prompt
    if admin_prompt_user == "3":
        findings.append({
            "category": "Windows UAC",
            "type": "Standard Users Auto-Elevated Without Prompt",
            "severity": "HIGH",
            "description": (
                "ConsentPromptBehaviorUser=3 means standard user elevation requests "
                "are automatically approved without a consent prompt, weakening UAC."
            ),
            "mitigation": "Set ConsentPromptBehaviorUser to 0 (auto-deny) or 1 (credential prompt)."
        })

    # UAC fully disabled
    if enable_lua == "0":
        findings.append({
            "category": "Windows UAC",
            "type": "UAC Fully Disabled",
            "severity": "CRITICAL",
            "description": (
                "EnableLUA is set to 0 — User Account Control is completely disabled. "
                "All processes run with full administrator privileges without any elevation "
                "prompt. No UAC bypass is needed; any admin-group member has unrestricted access."
            ),
            "mitigation": (
                f"Enable UAC: Set EnableLUA to 1 at "
                f"HKLM\\{uac_key} via Group Policy or secpol.msc."
            ),
            "details": {
                "EnableLUA": enable_lua,
                "registry_key": f"HKLM\\{uac_key}",
            },
        })
        return findings  # No further UAC checks meaningful if disabled

    # Check consent prompt level
    if consent_level in UAC_CONSENT_LEVELS:
        description_text, severity = UAC_CONSENT_LEVELS[consent_level]
        if consent_level == "0":
            findings.append({
                "category": "Windows UAC",
                "type": "UAC Auto-Elevation (No Prompt)",
                "severity": severity,
                "description": (
                    f"ConsentPromptBehaviorAdmin is {consent_level}: {description_text}. "
                    "This allows processes to silently elevate to SYSTEM without user interaction, "
                    "making UAC bypass trivial."
                ),
                "mitigation": (
                    "Set ConsentPromptBehaviorAdmin to 2 (prompt for credentials on secure desktop) "
                    "via Group Policy → Windows Settings → Security Settings → Local Policies → "
                    "Security Options → UAC."
                ),
                "details": {
                    "ConsentPromptBehaviorAdmin": consent_level,
                    "meaning": description_text,
                },
            })

    # LocalAccountTokenFilterPolicy = 1 allows remote admins to get full tokens
    if local_admin_bypass == "1":
        findings.append({
            "category": "Windows UAC",
            "type": "LocalAccountTokenFilterPolicy Enabled",
            "severity": "HIGH",
            "description": (
                "LocalAccountTokenFilterPolicy is set to 1. This disables UAC remote "
                "restrictions, allowing local administrators to authenticate remotely with "
                "full administrator tokens (no split token). Combined with PsExec or WMI, "
                "this enables lateral movement without UAC prompts."
            ),
            "mitigation": (
                f"Set LocalAccountTokenFilterPolicy to 0 at HKLM\\{uac_key}, "
                "or remove the value entirely."
            ),
            "details": {
                "LocalAccountTokenFilterPolicy": local_admin_bypass,
            },
        })

    return findings


def _check_token_elevation_type() -> list[dict]:
    """
    Detect if the current user is a local admin running with a split token.
    A split token means UAC is active but a bypass could elevate without prompting.
    """
    findings = []

    # Check token elevation type via whoami /groups looking for Mandatory Level
    groups_raw = _run(["whoami", "/groups"])
    is_admin_group = "S-1-5-32-544" in groups_raw  # Administrators SID

    elevated_check = _run_powershell(
        "([Security.Principal.WindowsPrincipal]"
        "[Security.Principal.WindowsIdentity]::GetCurrent())"
        ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    is_elevated = elevated_check.strip().lower() == "true"

    if is_admin_group and not is_elevated:
        findings.append({
            "category": "Windows UAC",
            "type": "Admin User Running with Split Token",
            "severity": "MEDIUM",
            "description": (
                "The current user is a member of the local Administrators group but is running "
                "with a filtered (limited) token. A UAC bypass technique could allow elevation "
                "to full administrator without a credentials prompt."
            ),
            "mitigation": (
                "For high-security systems, remove the user from the local Administrators group "
                "and use 'Run as administrator' explicitly only when needed."
            ),
            "details": {
                "in_administrators_group": is_admin_group,
                "currently_elevated": is_elevated,
                "note": "UAC bypass techniques: eventvwr, fodhelper, msconfig, etc.",
            },
        })

    return findings


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of UAC-related privilege escalation findings."""
    if verbose:
        print("[*] Scanning UAC configuration for privilege escalation vectors...")

    findings: list[dict] = []

    if verbose:
        print("    Checking UAC registry settings...")
    findings.extend(_check_uac_settings())

    if verbose:
        print("    Checking token elevation type...")
    findings.extend(_check_token_elevation_type())

    if verbose:
        print(f"    Found {len(findings)} UAC finding(s).")

    return findings
