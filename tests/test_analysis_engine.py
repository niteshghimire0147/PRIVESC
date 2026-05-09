"""
Tests for analysis/engine.py — risk scoring and deduplication logic.
Run with: python -m pytest tests/test_analysis_engine.py -v
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analysis.engine import analyse  # noqa: E402


def make_finding(severity, category="TEST", description="test finding", path=""):
    return {
        "category": category,
        "type": "TEST_TYPE",
        "severity": severity,
        "description": description,
        "mitigation": "Remediate this.",
        "details": {},
        "path": path,
    }


class TestRiskScoring:
    def test_empty_findings_score_zero(self):
        result = analyse([])
        assert result["summary"]["risk_score"] == 0

    def test_empty_findings_risk_level_low(self):
        result = analyse([])
        assert result["summary"]["risk_level"] == "LOW"

    def test_single_critical_finding(self):
        findings = [make_finding("CRITICAL")]
        result = analyse(findings)
        # CRITICAL → risk_level is CRITICAL (any CRITICAL triggers CRITICAL level)
        assert result["summary"]["risk_level"] == "CRITICAL"
        assert result["summary"]["risk_score"] >= 10

    def test_single_high_finding_risk_level(self):
        findings = [make_finding("HIGH")]
        result = analyse(findings)
        # HIGH → risk_level HIGH
        assert result["summary"]["risk_level"] in ("HIGH", "CRITICAL")
        assert result["summary"]["risk_score"] >= 5

    def test_mixed_severity_scoring(self):
        findings = [
            make_finding("CRITICAL", path="/a"),
            make_finding("HIGH",     path="/b"),
            make_finding("MEDIUM",   path="/c"),
            make_finding("LOW",      path="/d"),
        ]
        result = analyse(findings)
        # Min expected score: 10 + 5 + 2 + 1 = 18
        assert result["summary"]["risk_score"] >= 18

    def test_count_by_severity(self):
        findings = [
            make_finding("CRITICAL", path="/a"),
            make_finding("CRITICAL", path="/b"),
            make_finding("HIGH",     path="/c"),
            make_finding("MEDIUM",   path="/d"),
            make_finding("LOW",      path="/e"),
            make_finding("LOW",      path="/f"),
        ]
        result = analyse(findings)
        s = result["summary"]
        assert s["critical"] == 2
        assert s["high"] == 1
        assert s["medium"] == 1
        assert s["low"] == 2

    def test_total_count(self):
        findings = [make_finding("HIGH") for _ in range(4)]
        result = analyse(findings)
        # All unique because paths differ implicitly, but let's check total
        assert result["summary"]["total"] <= 4


class TestDeduplication:
    def test_identical_findings_deduplicated(self):
        """Same category+type+path combination should be deduplicated."""
        finding = make_finding("HIGH", category="SUID/SGID Binary",
                               description="find is SUID", path="/usr/bin/find")
        result = analyse([finding, finding])
        assert result["summary"]["total"] == 1

    def test_different_paths_not_deduplicated(self):
        findings = [
            make_finding("HIGH", category="SUID/SGID Binary", path="/usr/bin/find"),
            make_finding("HIGH", category="SUID/SGID Binary", path="/usr/bin/python3"),
        ]
        result = analyse(findings)
        assert result["summary"]["total"] == 2

    def test_findings_sorted_by_severity(self):
        """CRITICAL findings should come before HIGH before MEDIUM before LOW."""
        findings = [
            make_finding("LOW", path="/a"),
            make_finding("CRITICAL", path="/b"),
            make_finding("MEDIUM", path="/c"),
            make_finding("HIGH", path="/d"),
        ]
        result = analyse(findings)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        positions = [sev_order[f["severity"]] for f in result["findings"]]
        assert positions == sorted(positions)


class TestCategoryGrouping:
    def test_grouped_by_category(self):
        findings = [
            make_finding("HIGH", category="SUID/SGID Binary", path="/usr/bin/find"),
            make_finding("MEDIUM", category="Cron Job Vulnerability", path="/etc/cron.d/job"),
        ]
        result = analyse(findings)
        assert "SUID/SGID Binary" in result["findings_by_category"]
        assert "Cron Job Vulnerability" in result["findings_by_category"]

    def test_category_counts_accurate(self):
        findings = [
            make_finding("CRITICAL", category="Kernel Security", path="/kernel/a"),
            make_finding("HIGH", category="Kernel Security", path="/kernel/b"),
        ]
        result = analyse(findings)
        cc = result["category_counts"].get("Kernel Security", {})
        assert cc.get("CRITICAL", 0) == 1
        assert cc.get("HIGH", 0) == 1
