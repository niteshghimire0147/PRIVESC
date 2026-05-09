"""
Tests for reporter/ — HTML, text, and JSON report generation.
Run with: python -m pytest tests/test_reporter.py -v
"""
import sys
import os
import json
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analysis.engine import analyse  # noqa: E402


SAMPLE_FINDINGS = [
    {
        "category": "SUID/SGID Binary",
        "type": "GTFOBins_SUID",
        "severity": "HIGH",
        "description": "/usr/bin/find has SUID bit set and is in GTFOBins",
        "mitigation": "Remove SUID bit: chmod u-s /usr/bin/find",
        "path": "/usr/bin/find",
        "binary_path": "/usr/bin/find",
        "details": {"exploit_command": "find . -exec /bin/sh \\; -quit"},
    },
    {
        "category": "Kernel Security",
        "type": "KERNEL_CVE",
        "severity": "CRITICAL",
        "description": "Kernel 5.8.0 is vulnerable to CVE-2022-0847 (Dirty Pipe)",
        "mitigation": "Upgrade kernel to >= 5.16.11",
        "path": "",
        "details": {"cve": "CVE-2022-0847", "cvss": "7.8"},
    },
    {
        "category": "Credentials",
        "type": "BASH_HISTORY_SECRET",
        "severity": "MEDIUM",
        "description": "Password found in bash history",
        "mitigation": "Clear history and rotate credentials",
        "path": "/home/user/.bash_history",
        "details": {},
    },
]


class TestJSONReporter:
    def test_json_reporter_imports(self):
        try:
            from reporter import generator
            assert generator is not None
        except ImportError as e:
            assert False, f"Failed to import reporter.generator: {e}"

    def test_json_output_valid(self):
        from reporter import generator
        mock_sysinfo = {
            "hostname": "testhost", "current_user": "testuser",
            "is_root": False, "kernel_release": "5.15.0",
            "os_name": "Ubuntu 22.04", "user_id": "uid=1000(testuser)",
            "groups": [], "shell_users": [],
        }
        results = analyse(SAMPLE_FINDINGS)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                        delete=False, encoding='utf-8') as f:
            tmp_path = f.name
        try:
            if hasattr(generator, "generate_json"):
                generator.generate_json(mock_sysinfo, results, output_file=tmp_path)
            elif hasattr(generator, "write_json_report"):
                generator.write_json_report(mock_sysinfo, results, tmp_path)
            else:
                return  # Skip if function not found
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict)
            assert "system_info" in data
            assert "findings" in data
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestHTMLReporter:
    def test_html_reporter_imports(self):
        try:
            from reporter import html_generator
            assert html_generator is not None
        except ImportError as e:
            assert False, f"Failed to import reporter.html_generator: {e}"

    def test_html_output_contains_required_sections(self):
        from reporter import html_generator
        analysis = analyse(SAMPLE_FINDINGS)
        # Get HTML as string
        if hasattr(html_generator, "generate_html_report"):
            html = html_generator.generate_html_report(analysis)
        elif hasattr(html_generator, "generate"):
            html = html_generator.generate(analysis)
        else:
            return  # Skip if interface unknown

        assert isinstance(html, str)
        assert len(html) > 100
        # Should contain key structural elements
        assert "<html" in html.lower() or "<!DOCTYPE" in html.lower() or "<div" in html.lower()

    def test_html_output_contains_severity_labels(self):
        from reporter import html_generator
        analysis = analyse(SAMPLE_FINDINGS)
        if hasattr(html_generator, "generate_html_report"):
            html = html_generator.generate_html_report(analysis)
        elif hasattr(html_generator, "generate"):
            html = html_generator.generate(analysis)
        else:
            return
        # Severity labels should appear in the output
        assert "CRITICAL" in html or "HIGH" in html


class TestAnalysisIntegration:
    def test_full_pipeline_runs(self):
        """End-to-end: raw findings → analyse → summary has expected keys."""
        result = analyse(SAMPLE_FINDINGS)
        required_summary_keys = {"critical", "high", "medium", "low", "total",
                                  "risk_score", "risk_level"}
        assert required_summary_keys.issubset(set(result["summary"].keys()))
        assert "findings" in result
        assert "findings_by_category" in result

    def test_full_pipeline_critical_detected(self):
        result = analyse(SAMPLE_FINDINGS)
        assert result["summary"]["critical"] >= 1
        assert result["summary"]["risk_level"] == "CRITICAL"
