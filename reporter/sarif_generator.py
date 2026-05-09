"""
sarif_generator.py — SARIF 2.1.0 output for GitHub Security tab integration.

Usage:
    python3 main.py -f sarif -o results.sarif

GitHub Actions integration:
    - uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: results.sarif
"""

import json
import datetime
from typing import Any


# SARIF severity → GitHub annotation levels
SEVERITY_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}

TOOL_NAME    = "PRIVESC"
TOOL_VERSION = "2.1.0"
TOOL_URI     = "https://github.com/niteshghimire/privesc-toolkit"
TOOL_INFO_URI = "https://github.com/niteshghimire/privesc-toolkit#readme"


def _make_rule(finding: dict) -> dict:
    """Convert a unique finding type into a SARIF rule descriptor."""
    rule_id = _rule_id(finding)
    severity = finding.get("severity", "LOW")
    return {
        "id": rule_id,
        "name": rule_id.replace("-", " ").title(),
        "shortDescription": {"text": finding.get("type", "Unknown")},
        "fullDescription": {"text": finding.get("description", "")},
        "helpUri": TOOL_INFO_URI,
        "defaultConfiguration": {
            "level": SEVERITY_LEVEL_MAP.get(severity, "warning")
        },
        "properties": {
            "tags": [finding.get("category", ""), severity],
            "security-severity": _cvss_approximation(severity),
        },
        "help": {
            "text": finding.get("mitigation", "See finding details for remediation guidance."),
            "markdown": f"## Mitigation\n\n{finding.get('mitigation', '')}",
        },
    }


def _rule_id(finding: dict) -> str:
    """Generate a stable rule ID from category + type."""
    cat  = finding.get("category", "Unknown").upper().replace(" ", "-").replace("/", "-")
    typ  = finding.get("type", "Unknown").upper().replace(" ", "-").replace("/", "-")
    return f"PRIVESC-{cat}-{typ}"[:60]


def _cvss_approximation(severity: str) -> str:
    """Map severity to a CVSS-like numeric string for GitHub."""
    return {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.0"}.get(severity, "2.0")


def generate_sarif(system_info: dict, results: dict, output_file: str | None = None) -> str:
    """
    Generate a SARIF 2.1.0 document from scan results.

    Args:
        system_info: dict from system_info.collect() or windows_system_info.collect()
        results:     dict from analysis engine containing 'findings' and 'summary'
        output_file: optional file path to write the SARIF JSON

    Returns:
        SARIF JSON string
    """
    findings: list[dict] = results.get("findings", [])
    summary:  dict       = results.get("summary", {})

    # Build deduplicated rule list
    seen_rules: dict = {}
    for f in findings:
        rid = _rule_id(f)
        if rid not in seen_rules:
            seen_rules[rid] = _make_rule(f)

    # Build results list
    sarif_results = []
    for idx, f in enumerate(findings):
        rid    = _rule_id(f)
        level  = SEVERITY_LEVEL_MAP.get(f.get("severity", "LOW"), "warning")
        detail = f.get("description", "")
        mitigation = f.get("mitigation", "")
        path_target = (
            f.get("details", {}).get("path")
            or f.get("details", {}).get("executable")
            or f.get("details", {}).get("file")
            or f.get("details", {}).get("directory")
            or f.get("details", {}).get("service_name")
            or "/"
        )

        sarif_result = {
            "ruleId": rid,
            "level": level,
            "message": {
                "text": detail,
                "markdown": (
                    f"**{f.get('type', '')}**\n\n{detail}\n\n"
                    f"**Mitigation:** {mitigation}"
                ),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(path_target).replace("\\", "/").lstrip("/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{
                    "name": f.get("category", ""),
                    "fullyQualifiedName": f"{f.get('category', '')} / {f.get('type', '')}",
                    "kind": "function",
                }],
            }],
            "properties": {
                "severity":   f.get("severity", "LOW"),
                "category":   f.get("category", ""),
                "mitigation": mitigation,
                "details":    f.get("details", {}),
            },
        }
        sarif_results.append(sarif_result)

    # Assemble SARIF document
    sarif_doc: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":            TOOL_NAME,
                    "version":         TOOL_VERSION,
                    "informationUri":  TOOL_INFO_URI,
                    "organization":    "PRIVESC Project",
                    "fullName":        "PRIVESC Cross-Platform Privilege Escalation Scanner",
                    "semanticVersion": TOOL_VERSION,
                    "rules":           list(seen_rules.values()),
                    "properties": {
                        "tags":        ["security", "sast", "privilege-escalation"],
                        "supportedPlatforms": ["linux", "windows"],
                    },
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.datetime.utcnow().isoformat() + "Z",
                "toolExecutionNotifications": [],
            }],
            "artifacts": [],
            "properties": {
                "hostname":     system_info.get("hostname", "unknown"),
                "os":           system_info.get("os_version") or system_info.get("os_name", "unknown"),
                "risk_level":   summary.get("risk_level", "UNKNOWN"),
                "risk_score":   summary.get("risk_score", 0),
                "total_findings": summary.get("total", 0),
            },
        }],
        "inlineExternalProperties": [],
    }

    sarif_json = json.dumps(sarif_doc, indent=2)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(sarif_json)

    return sarif_json
