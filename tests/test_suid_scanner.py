"""
Tests for modules/suid_scanner.py — SUID/SGID binary detection and GTFOBins lookup.
Run with: python -m pytest tests/test_suid_scanner.py -v
"""
import sys
import os
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestGTFOBinsDatabase:
    """Test the GTFOBins JSON data file is valid and contains expected entries."""

    def setup_method(self):
        data_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "gtfobins.json"
        )
        with open(data_path, "r", encoding="utf-8") as f:
            self.gtfobins = json.load(f)

    def test_database_loads(self):
        assert isinstance(self.gtfobins, (dict, list))
        assert len(self.gtfobins) > 0

    def test_known_binary_find_present(self):
        """'find' is one of the most commonly exploited SUID binaries."""
        if isinstance(self.gtfobins, dict):
            assert "find" in self.gtfobins
        else:
            names = [entry.get("name", entry.get("binary", "")) for entry in self.gtfobins]
            assert "find" in names

    def test_known_binary_python3_or_python(self):
        """Python is exploitable via SUID."""
        if isinstance(self.gtfobins, dict):
            has_python = "python" in self.gtfobins or "python3" in self.gtfobins
        else:
            names = [entry.get("name", entry.get("binary", "")) for entry in self.gtfobins]
            has_python = "python" in names or "python3" in names
        assert has_python

    def test_minimum_entry_count(self):
        """Database should have at least 20 exploitable binaries."""
        count = len(self.gtfobins) if isinstance(self.gtfobins, dict) else len(self.gtfobins)
        assert count >= 20


class TestSUIDScannerImport:
    """Test that the SUID scanner module imports and exposes expected interface."""

    def test_module_imports(self):
        try:
            from modules import suid_scanner
            assert suid_scanner is not None
        except ImportError as e:
            assert False, f"Failed to import suid_scanner: {e}"

    def test_run_function_exists(self):
        from modules import suid_scanner
        assert hasattr(suid_scanner, "scan") or hasattr(suid_scanner, "run") or hasattr(suid_scanner, "scan_suid_sgid")

    def test_returns_list(self):
        """run() must return a list (possibly empty on non-Linux or no SUID binaries)."""
        from modules import suid_scanner
        if hasattr(suid_scanner, "scan"):
            result = suid_scanner.scan(verbose=False)
            assert isinstance(result, list)
        elif hasattr(suid_scanner, "run"):
            result = suid_scanner.run(verbose=False)
            assert isinstance(result, list)
        elif hasattr(suid_scanner, "scan_suid_sgid"):
            result = suid_scanner.scan_suid_sgid()
            assert isinstance(result, list)

    def test_finding_schema_if_results(self):
        """Each finding must have required keys."""
        from modules import suid_scanner
        required_keys = {"category", "type", "severity"}
        if hasattr(suid_scanner, "scan"):
            results = suid_scanner.scan(verbose=False)
        elif hasattr(suid_scanner, "run"):
            results = suid_scanner.run(verbose=False)
        else:
            results = suid_scanner.scan_suid_sgid()
        for finding in results:
            assert isinstance(finding, dict)
            missing = required_keys - set(finding.keys())
            assert not missing, f"Finding missing keys: {missing}"
            # Scanners may use 'notes' or 'description' for human-readable text
            has_desc = "notes" in finding or "description" in finding
            assert has_desc, "Finding has neither 'notes' nor 'description' key"
