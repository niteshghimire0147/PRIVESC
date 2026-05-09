"""
priority_engine.py — Enhanced Severity Prioritization Engine.

Computes a richer risk score per finding using factors beyond raw severity:
  - Base severity weight (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1)
  - Exploitability: is a public PoC known?
  - Privilege required: does the current user already have partial access?
  - Attack complexity: how many steps required?
  - System exposure: is this an internet-facing or critical system indicator?
  - Active exploit availability (from threat intel enrichment)

The result is a normalized 0-100 Priority Score per finding, plus an
enhanced overall risk classification.
"""

from __future__ import annotations
from typing import Any


# Base severity weights (same as engine.py)
BASE_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}

# Exploitability bonus: added when a finding contains exploit examples or CVE refs
EXPLOIT_BONUS = 1.5

# Complexity modifier: multiply by factor based on inferred attack steps
COMPLEXITY_FACTORS = {
    "trivial":  1.5,   # Single command, no prerequisites
    "low":      1.2,   # Few steps, reliable
    "medium":   1.0,   # Multiple steps
    "high":     0.7,   # Complex prerequisites
}

# Finding types known to be trivially exploitable
TRIVIAL_TYPES = {
    "alwaysinstallelevated", "nopasswd", "writable service executable",
    "writable task executable", "autologon credentials", "uac fully disabled",
    "suid binary with gtfobins exploit", "dangerous privilege: seimpersonateprivilege",
}

# Finding types with higher complexity
HIGH_COMPLEXITY_TYPES = {
    "kernel cve", "dll hijacking", "missing path directory",
    "safedsllsearchmode disabled",
}


def _infer_complexity(finding: dict) -> str:
    """Estimate attack complexity from finding type and details."""
    typ = finding.get("type", "").lower()
    for t in TRIVIAL_TYPES:
        if t in typ:
            return "trivial"
    for t in HIGH_COMPLEXITY_TYPES:
        if t in typ:
            return "high"
    # Check if exploit example is present (indicator of low complexity)
    details = finding.get("details", {})
    if details.get("exploit_example") or details.get("in_gtfobins"):
        return "low"
    return "medium"


def _has_public_exploit(finding: dict) -> bool:
    """Return True if the finding references a known public exploit or CVE PoC."""
    details = finding.get("details", {})
    if details.get("exploit_example"):
        return True
    if details.get("in_gtfobins"):
        return True
    cve = details.get("cve", "")
    if cve and cve.startswith("CVE-"):
        return True
    return False


def compute_priority_score(finding: dict) -> float:
    """
    Compute a 0-100 priority score for a single finding.

    Higher score = higher priority for remediation.
    """
    severity = finding.get("severity", "LOW")
    base = BASE_WEIGHTS.get(severity, 1) * 10  # 10, 50, 20, 10 → scale to 0-100

    # Exploitability bonus
    if _has_public_exploit(finding):
        base *= EXPLOIT_BONUS

    # Complexity factor
    complexity = _infer_complexity(finding)
    base *= COMPLEXITY_FACTORS.get(complexity, 1.0)

    # Threat intel: active exploitation in the wild (if enriched)
    if finding.get("threat_intel", {}).get("exploited_in_wild"):
        base *= 1.4

    # Threat intel: EPSS score (probability of exploitation within 30 days)
    epss = finding.get("threat_intel", {}).get("epss_score", 0.0)
    if epss > 0.5:
        base *= 1.3
    elif epss > 0.2:
        base *= 1.1

    # Cap at 100
    return min(round(base, 1), 100.0)


def enrich_with_priority(findings: list[dict]) -> list[dict]:
    """
    Add priority_score and complexity to each finding in-place.
    Also sorts findings by priority_score descending.
    """
    for finding in findings:
        finding["priority_score"]      = compute_priority_score(finding)
        finding["attack_complexity"]   = _infer_complexity(finding)
        finding["has_public_exploit"]  = _has_public_exploit(finding)
    findings.sort(key=lambda f: f["priority_score"], reverse=True)
    return findings


def compute_enhanced_risk_summary(findings: list[dict]) -> dict[str, Any]:
    """
    Compute an enhanced risk summary that goes beyond the basic weighted score.

    Returns:
        dict with enhanced_risk_score, priority_distribution, top_priorities,
        exploitable_count, remediation_phases
    """
    enriched = [f for f in findings if "priority_score" in f]
    if not enriched:
        enrich_with_priority(findings)
        enriched = findings

    total_score = sum(f.get("priority_score", 0) for f in enriched)

    exploitable = [f for f in enriched if f.get("has_public_exploit")]

    # Group into remediation phases
    phase1 = [f for f in enriched if f.get("priority_score", 0) >= 80]   # Immediate
    phase2 = [f for f in enriched if 50 <= f.get("priority_score", 0) < 80]  # Short-term
    phase3 = [f for f in enriched if 20 <= f.get("priority_score", 0) < 50]  # Medium-term
    phase4 = [f for f in enriched if f.get("priority_score", 0) < 20]         # Long-term

    return {
        "enhanced_risk_score":   round(total_score / max(len(enriched), 1), 1),
        "exploitable_count":     len(exploitable),
        "exploitable_pct":       round(len(exploitable) / max(len(enriched), 1) * 100, 1),
        "remediation_phases": {
            "phase1_immediate":   len(phase1),
            "phase2_short_term":  len(phase2),
            "phase3_medium_term": len(phase3),
            "phase4_long_term":   len(phase4),
        },
        "top_priorities": [
            {
                "category":      f.get("category"),
                "type":          f.get("type"),
                "severity":      f.get("severity"),
                "priority_score": f.get("priority_score"),
                "complexity":    f.get("attack_complexity"),
            }
            for f in enriched[:5]
        ],
    }
