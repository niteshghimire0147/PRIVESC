"""
engine.py — Step 3: Risk analysis and scoring engine.

Aggregates all scanner findings, normalises severity levels,
assigns numeric risk scores, deduplicates entries, and produces
a structured summary ready for report generation.
"""

# Severity ordering — higher number = higher risk
SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# Human-readable severity colour codes (for terminal output)
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # Bright red
    "HIGH":     "\033[93m",   # Yellow
    "MEDIUM":   "\033[94m",   # Blue
    "LOW":      "\033[92m",   # Green
    "INFO":     "\033[0m",    # Default
    "RESET":    "\033[0m",
}

# Category display order in reports
CATEGORY_ORDER = [
    "SUID/SGID Binary",
    "Weak File Permissions",
    "Misconfigured Service",
    "Cron Job Vulnerability",
    "Kernel Security",
    "Linux Capabilities",
    "Credentials",
    "PATH Hijacking",
]


def _normalise_severity(severity_str):
    """Map any severity string to one of our four standard levels."""
    if not severity_str:
        return "LOW"
    s = severity_str.strip().upper()
    if s in SEVERITY_RANK:
        return s
    if s in ("CRIT", "CRITICAL"):
        return "CRITICAL"
    if s in ("WARN", "WARNING"):
        return "MEDIUM"
    return "LOW"


def _dedup_findings(findings):
    """
    Remove duplicate findings.
    Two findings are considered duplicates if they share the same
    category, type, and path/binary_name.
    """
    seen = set()
    deduped = []
    for f in findings:
        key = (
            f.get("category", ""),
            f.get("type", ""),
            f.get("path", f.get("binary_path", f.get("script_path", f.get("setting", "")))),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def analyse(all_findings):
    """
    Process and score all findings from all scanner modules.

    Args:
        all_findings (list[dict]): Raw findings from all scanners.

    Returns:
        dict: {
            "summary": {
                "critical": int,
                "high": int,
                "medium": int,
                "low": int,
                "total": int,
                "risk_score": int,   # weighted composite score
                "risk_level": str,   # CRITICAL / HIGH / MEDIUM / LOW
            },
            "findings": list[dict],          # all findings, sorted by severity
            "findings_by_category": dict,    # grouped by category
            "category_counts": dict,         # {category: {CRITICAL: n, HIGH: n, ...}}
        }
    """
    # Normalise severity on all findings
    for f in all_findings:
        f["severity"] = _normalise_severity(f.get("severity", "LOW"))

    # Deduplicate
    findings = _dedup_findings(all_findings)

    # Sort: severity descending, then category order, then path
    def sort_key(f):
        sev = SEVERITY_RANK.get(f.get("severity", "LOW"), 0)
        cat_idx = CATEGORY_ORDER.index(f.get("category")) if f.get("category") in CATEGORY_ORDER else 99
        path = f.get("path", f.get("binary_path", f.get("script_path", "")))
        return (-sev, cat_idx, path)

    findings.sort(key=sort_key)

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    # Composite risk score (weighted):
    # CRITICAL × 10, HIGH × 5, MEDIUM × 2, LOW × 1
    risk_score = (
        counts["CRITICAL"] * 10 +
        counts["HIGH"] * 5 +
        counts["MEDIUM"] * 2 +
        counts["LOW"] * 1
    )

    # Overall risk level based on score thresholds
    if counts["CRITICAL"] > 0 or risk_score >= 20:
        risk_level = "CRITICAL"
    elif counts["HIGH"] > 0 or risk_score >= 10:
        risk_level = "HIGH"
    elif counts["MEDIUM"] > 0 or risk_score >= 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Group by category
    findings_by_category = {}
    category_counts = {}
    for f in findings:
        cat = f.get("category", "Uncategorised")
        findings_by_category.setdefault(cat, []).append(f)
        cc = category_counts.setdefault(cat, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        cc[f.get("severity", "LOW")] += 1

    summary = {
        "critical": counts["CRITICAL"],
        "high":     counts["HIGH"],
        "medium":   counts["MEDIUM"],
        "low":      counts["LOW"],
        "total":    len(findings),
        "risk_score":  risk_score,
        "risk_level":  risk_level,
    }

    return {
        "summary": summary,
        "findings": findings,
        "findings_by_category": findings_by_category,
        "category_counts": category_counts,
    }


def colorise(severity, text):
    """Wrap text in terminal colour codes for the given severity level."""
    color = SEVERITY_COLORS.get(severity, "")
    reset = SEVERITY_COLORS["RESET"]
    return f"{color}{text}{reset}"


def severity_badge(severity):
    """Return a fixed-width severity badge string for terminal output."""
    badges = {
        "CRITICAL": "[CRITICAL]",
        "HIGH":     "[HIGH]    ",
        "MEDIUM":   "[MEDIUM]  ",
        "LOW":      "[LOW]     ",
    }
    return badges.get(severity, f"[{severity}]")
