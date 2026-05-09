"""
diff_engine.py — Differential scan mode.

Compare two scan JSON reports and produce a structured diff showing:
  - NEW findings (introduced since last scan)
  - FIXED findings (resolved since last scan)
  - CHANGED findings (severity changed)
  - PERSISTENT findings (unchanged)

Usage:
    python3 main.py --compare old_scan.json new_scan.json

Returns:
    dict with keys: new, fixed, changed, persistent, summary
"""

import json
from typing import Any


def _load_report(path: str) -> dict:
    """Load a PRIVESC JSON report from disk."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _finding_key(finding: dict) -> str:
    """
    Generate a stable identity key for a finding.
    Uses category + type + the most specific path/target available.
    """
    cat  = finding.get("category", "").strip()
    typ  = finding.get("type", "").strip()
    details = finding.get("details", {})
    target = (
        details.get("path")
        or details.get("executable")
        or details.get("file")
        or details.get("directory")
        or details.get("service_name")
        or details.get("privilege")
        or details.get("cve")
        or ""
    )
    return f"{cat}|{typ}|{target}".lower()


def compare(old_path: str, new_path: str) -> dict:
    """
    Compare two PRIVESC JSON scan reports.

    Args:
        old_path: path to the baseline/older scan JSON
        new_path: path to the current/newer scan JSON

    Returns:
        dict with:
            new        – findings that appear only in new scan
            fixed      – findings that appeared in old but not new (resolved)
            changed    – findings present in both but with different severity
            persistent – findings present in both with same severity
            summary    – counts + risk delta
    """
    old_report = _load_report(old_path)
    new_report = _load_report(new_path)

    old_findings: list[dict] = old_report.get("findings", [])
    new_findings: list[dict] = new_report.get("findings", [])

    # Build keyed dictionaries
    old_map: dict[str, dict] = {_finding_key(f): f for f in old_findings}
    new_map: dict[str, dict] = {_finding_key(f): f for f in new_findings}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    result: dict[str, Any] = {
        "new":        [],
        "fixed":      [],
        "changed":    [],
        "persistent": [],
        "summary":    {},
    }

    # New findings
    for key in new_keys - old_keys:
        result["new"].append(new_map[key])

    # Fixed findings
    for key in old_keys - new_keys:
        result["fixed"].append(old_map[key])

    # Changed or persistent
    for key in old_keys & new_keys:
        old_f = old_map[key]
        new_f = new_map[key]
        if old_f.get("severity") != new_f.get("severity"):
            result["changed"].append({
                "finding":      new_f,
                "old_severity": old_f.get("severity"),
                "new_severity": new_f.get("severity"),
            })
        else:
            result["persistent"].append(new_f)

    # Summary
    old_summary = old_report.get("summary", {})
    new_summary = new_report.get("summary", {})

    result["summary"] = {
        "new_count":        len(result["new"]),
        "fixed_count":      len(result["fixed"]),
        "changed_count":    len(result["changed"]),
        "persistent_count": len(result["persistent"]),

        "old_risk_level":   old_summary.get("risk_level", "UNKNOWN"),
        "new_risk_level":   new_summary.get("risk_level", "UNKNOWN"),
        "old_risk_score":   old_summary.get("risk_score", 0),
        "new_risk_score":   new_summary.get("risk_score", 0),
        "risk_delta":       new_summary.get("risk_score", 0) - old_summary.get("risk_score", 0),

        "old_hostname":     old_report.get("system_info", {}).get("hostname", "unknown"),
        "new_hostname":     new_report.get("system_info", {}).get("hostname", "unknown"),
        "old_scan_time":    old_report.get("report_metadata", {}).get("generated_at", ""),
        "new_scan_time":    new_report.get("report_metadata", {}).get("generated_at", ""),

        "trend": (
            "IMPROVED"   if len(result["fixed"]) > len(result["new"]) else
            "WORSENED"   if len(result["new"])   > len(result["fixed"]) else
            "UNCHANGED"
        ),
    }

    return result


def render_diff_text(diff: dict, use_color: bool = True) -> str:
    """Render a diff result as a human-readable text report."""
    C = {
        "RED":    "\033[91m" if use_color else "",
        "GREEN":  "\033[92m" if use_color else "",
        "YELLOW": "\033[93m" if use_color else "",
        "CYAN":   "\033[96m" if use_color else "",
        "BOLD":   "\033[1m"  if use_color else "",
        "RESET":  "\033[0m"  if use_color else "",
    }

    s = diff["summary"]
    lines = [
        "",
        f"{C['BOLD']}{'═'*70}{C['RESET']}",
        f"{C['BOLD']}{C['CYAN']}  DIFFERENTIAL SCAN REPORT{C['RESET']}",
        f"{'═'*70}",
        f"  Baseline scan : {s['old_scan_time']}  ({s['old_hostname']})",
        f"  Current scan  : {s['new_scan_time']}  ({s['new_hostname']})",
        "",
        f"  Risk level    : {s['old_risk_level']} → {s['new_risk_level']}",
        f"  Risk score    : {s['old_risk_score']} → {s['new_risk_score']}  "
        f"(delta: {'+' if s['risk_delta'] >= 0 else ''}{s['risk_delta']})",
        f"  Trend         : {C['GREEN'] if s['trend']=='IMPROVED' else C['RED'] if s['trend']=='WORSENED' else C['YELLOW']}{s['trend']}{C['RESET']}",
        "",
        f"  {'─'*66}",
        f"  {C['RED']}NEW      : {s['new_count']:3d} findings{C['RESET']}  |  "
        f"{C['GREEN']}FIXED    : {s['fixed_count']:3d} findings{C['RESET']}",
        f"  {C['YELLOW']}CHANGED  : {s['changed_count']:3d} findings{C['RESET']}  |  "
        f"PERSISTENT: {s['persistent_count']:3d} findings",
        f"{'═'*70}",
    ]

    if diff["new"]:
        lines.append(f"\n{C['RED']}{C['BOLD']}── NEW FINDINGS (requires immediate attention) ──{C['RESET']}")
        for f in diff["new"]:
            lines.append(f"  [{f['severity']:<8}]  {f['category']} → {f['type']}")
            lines.append(f"              {f.get('description','')[:100]}")

    if diff["fixed"]:
        lines.append(f"\n{C['GREEN']}{C['BOLD']}── FIXED / RESOLVED FINDINGS ──{C['RESET']}")
        for f in diff["fixed"]:
            lines.append(f"  ✓ [{f['severity']:<8}]  {f['category']} → {f['type']}")

    if diff["changed"]:
        lines.append(f"\n{C['YELLOW']}{C['BOLD']}── SEVERITY CHANGED ──{C['RESET']}")
        for c in diff["changed"]:
            f = c["finding"]
            lines.append(
                f"  [{c['old_severity']:<8}] → [{c['new_severity']:<8}]  "
                f"{f['category']} → {f['type']}"
            )

    lines.append("")
    return "\n".join(lines)
