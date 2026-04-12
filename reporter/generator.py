"""
generator.py — Step 4: Report generation.

Produces two output formats:
  - TEXT: Human-readable report with sections, severity badges, and mitigations.
  - JSON: Machine-readable structured report for further processing.
"""

import json
import datetime
from analysis.engine import SEVERITY_COLORS, CATEGORY_ORDER


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _severity_label(severity):
    labels = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH    ",
        "MEDIUM":   "MEDIUM  ",
        "LOW":      "LOW     ",
    }
    return labels.get(severity, severity)


def _color(severity, text, use_color=True):
    if not use_color:
        return text
    color = SEVERITY_COLORS.get(severity, "")
    reset = SEVERITY_COLORS["RESET"]
    return f"{color}{text}{reset}"


def _divider(char="=", width=72):
    return char * width


def _section_header(title, char="─", width=72):
    return f"\n{char * 3} {title} {char * (width - len(title) - 5)}"


# ─── Text Report ──────────────────────────────────────────────────────────────

def _build_text_report(system_info, results, use_color=True):
    """Build the full text report as a list of lines."""
    lines = []
    summary = results["summary"]
    findings = results["findings"]
    findings_by_category = results["findings_by_category"]

    # ── Banner ──
    lines.append(_divider("═"))
    lines.append("  LINUX PRIVILEGE ESCALATION SCANNER — SECURITY REPORT")
    lines.append(_divider("═"))
    lines.append(f"  Generated : {_now()}")
    lines.append(f"  Hostname  : {system_info.get('hostname', 'N/A')}")
    lines.append(f"  User      : {system_info.get('current_user', 'N/A')}  "
                 f"({'ROOT' if system_info.get('is_root') else 'non-root'})")
    lines.append(f"  Kernel    : {system_info.get('kernel_release', 'N/A')}")
    lines.append(f"  OS        : {system_info.get('os_name', 'N/A')}")
    lines.append(f"  ID output : {system_info.get('user_id', 'N/A')}")
    lines.append(_divider("═"))

    # ── Executive Summary ──
    lines.append(_section_header("EXECUTIVE SUMMARY"))
    risk_level = summary["risk_level"]
    risk_line = f"  Overall Risk Level: {_color(risk_level, risk_level, use_color)}"
    lines.append(risk_line)
    lines.append(f"  Risk Score        : {summary['risk_score']}")
    lines.append("")
    crit = summary["critical"]
    high = summary["high"]
    med = summary["medium"]
    low = summary["low"]
    lines.append(
        f"  {_color('CRITICAL', f'CRITICAL : {crit:>4}', use_color)}  |  "
        f"{_color('HIGH',     f'HIGH     : {high:>4}', use_color)}  |  "
        f"{_color('MEDIUM',   f'MEDIUM   : {med:>4}', use_color)}  |  "
        f"{_color('LOW',      f'LOW      : {low:>4}', use_color)}"
    )
    lines.append(f"  Total Findings    : {summary['total']}")

    # ── Users with shell access ──
    shell_users = system_info.get("shell_users", [])
    if shell_users:
        lines.append(_section_header("USERS WITH SHELL ACCESS"))
        for u in shell_users:
            lines.append(f"  UID {u['uid']:>6}  {u['user']:<20}  Shell: {u['shell']}")

    # ── Category summary table ──
    lines.append(_section_header("FINDINGS BY CATEGORY"))
    lines.append(f"  {'Category':<30} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'TOTAL':>6}")
    lines.append(f"  {'-'*30} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*6}")

    ordered_cats = [c for c in CATEGORY_ORDER if c in findings_by_category]
    other_cats = [c for c in findings_by_category if c not in CATEGORY_ORDER]
    for cat in ordered_cats + other_cats:
        cc = results["category_counts"].get(cat, {})
        total = sum(cc.values())
        lines.append(
            f"  {cat:<30} "
            f"{cc.get('CRITICAL',0):>5} "
            f"{cc.get('HIGH',0):>5} "
            f"{cc.get('MEDIUM',0):>5} "
            f"{cc.get('LOW',0):>5} "
            f"{total:>6}"
        )

    # ── Detailed Findings ──
    if not findings:
        lines.append("\n  No findings detected. The system appears well-hardened.")
        lines.append(_divider("═"))
        return "\n".join(lines)

    lines.append(_section_header("DETAILED FINDINGS"))

    for i, f in enumerate(findings, 1):
        severity = f.get("severity", "LOW")
        category = f.get("category", "Unknown")
        ftype = f.get("type", "Unknown")

        # Path resolution — different modules use different keys
        path = (
            f.get("path") or
            f.get("binary_path") or
            f.get("script_path") or
            f.get("setting") or
            "N/A"
        )

        # Severity badge
        badge = _color(severity, f"[{_severity_label(severity).strip()}]", use_color)

        lines.append(f"\n  {_divider('-', 70)}")
        lines.append(f"  {badge}  #{i:03d}  {category} → {ftype}")
        lines.append(f"  {_divider('-', 70)}")
        lines.append(f"  Path/Target : {path}")

        # Category-specific extra fields
        if f.get("bit_type"):
            lines.append(f"  Bit Type    : {f['bit_type']}")
            lines.append(f"  In GTFOBins : {'Yes ⚠' if f.get('in_gtfobins') else 'No'}")
        if f.get("schedule"):
            lines.append(f"  Schedule    : {f['schedule']}")
            lines.append(f"  Runs As     : {f.get('user', 'unknown')}")
        if f.get("service"):
            lines.append(f"  Service     : {f['service']}")
            lines.append(f"  Runs As     : {f.get('runs_as', 'unknown')}")
        if f.get("cve_id"):
            lines.append(f"  CVE ID      : {f['cve_id']}" + (f"  ({f.get('cve_name', '')})" if f.get('cve_name') else ""))
        if f.get("capabilities"):
            lines.append(f"  Capabilities: {f['capabilities']}")
        if f.get("permissions"):
            lines.append(f"  Permissions : {f['permissions']}")

        # Notes
        notes = f.get("notes", "")
        if notes:
            lines.append("  " + _divider("·", 68))
            lines.append("  DESCRIPTION:")
            for note_line in notes.splitlines():
                lines.append(f"    {note_line}")

        # Exploit example
        exploit = f.get("exploit_example", "")
        if exploit:
            lines.append("  " + _divider("·", 68))
            lines.append("  EXPLOIT EXAMPLE (for authorised testing only):")
            lines.append(f"    {exploit}")

        # Reference
        ref = f.get("reference", "")
        if ref:
            lines.append(f"  Reference   : {ref}")

        # Mitigation
        mitigation = f.get("mitigation", "")
        if mitigation:
            lines.append("  " + _divider("·", 68))
            lines.append("  MITIGATION:")
            for mit_line in mitigation.splitlines():
                lines.append(f"    {mit_line}")

    # ── Footer ──
    lines.append(f"\n{_divider('═')}")
    lines.append("  END OF REPORT")
    lines.append(f"  This report is for authorised security testing and educational purposes only.")
    lines.append(_divider("═"))

    return "\n".join(lines)


# ─── JSON Report ──────────────────────────────────────────────────────────────

def _build_json_report(system_info, results):
    """Build the structured JSON report as a dict."""
    return {
        "report_metadata": {
            "generated_at": _now(),
            "tool": "Linux Privilege Escalation Automation Toolkit",
            "version": "1.0.0",
        },
        "system_info": {
            "hostname": system_info.get("hostname"),
            "current_user": system_info.get("current_user"),
            "user_id": system_info.get("user_id"),
            "is_root": system_info.get("is_root"),
            "groups": system_info.get("groups"),
            "kernel_release": system_info.get("kernel_release"),
            "kernel_version": system_info.get("kernel_version"),
            "os_name": system_info.get("os_name"),
            "os_version": system_info.get("os_version"),
            "shell_users": system_info.get("shell_users", []),
        },
        "summary": results["summary"],
        "category_counts": results["category_counts"],
        "findings": results["findings"],
    }


# ─── Public API ───────────────────────────────────────────────────────────────

def generate_text(system_info, results, output_file=None, use_color=True):
    """
    Generate and optionally write the text report.

    Args:
        system_info (dict): From modules/system_info.collect().
        results (dict): From analysis/engine.analyse().
        output_file (str|None): If given, write report to this file path.
        use_color (bool): Include ANSI colour codes (False for file output).

    Returns:
        str: The full text report.
    """
    report = _build_text_report(system_info, results, use_color=use_color)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
    return report


def generate_json(system_info, results, output_file=None):
    """
    Generate and optionally write the JSON report.

    Args:
        system_info (dict): From modules/system_info.collect().
        results (dict): From analysis/engine.analyse().
        output_file (str|None): If given, write report to this file path.

    Returns:
        str: The JSON report as a string.
    """
    data = _build_json_report(system_info, results)
    report_str = json.dumps(data, indent=2, default=str)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report_str)
    return report_str
