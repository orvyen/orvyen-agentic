"""
Test suite for SARIF 2.1.0 reporter (GitHub Advanced Security format).
"""

import json
import tempfile
import unittest
from pathlib import Path

from orvyen.core.engine import ScanEngine
from orvyen.core.models import Severity
from orvyen.reporters.sarif_reporter import SARIFReporter
from orvyen.cli import main


class TestSARIFReporter(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.vulnerable_dir = self.fixtures_dir / "vulnerable_agent"
        self.secure_dir = self.fixtures_dir / "secure_agent"

    def test_sarif_schema_compliance(self):
        """Verify SARIF 2.1.0 schema declaration and driver metadata."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        sarif_json = SARIFReporter.generate(result)
        doc = json.loads(sarif_json)

        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", doc["$schema"])
        self.assertIn("runs", doc)
        self.assertEqual(len(doc["runs"]), 1)

        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "Orvyen Agentic")
        self.assertEqual(driver["version"], "0.3.0")
        self.assertIn("informationUri", driver)

    def test_sarif_rules_catalogue(self):
        """Verify driver rules define all OAG rules with remediation and standards mapping."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()
        doc = SARIFReporter.generate_dict(result)

        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}

        # Check OAG-001 through OAG-012 are registered in catalogue
        for i in range(1, 13):
            expected_id = f"OAG-{i:03d}"
            self.assertIn(expected_id, rule_ids, f"Rule {expected_id} missing from SARIF rules catalogue")

        sample_rule = next(r for r in rules if r["id"] == "OAG-001")
        self.assertIn("shortDescription", sample_rule)
        self.assertIn("fullDescription", sample_rule)
        self.assertIn("help", sample_rule)
        self.assertIn("defaultConfiguration", sample_rule)
        self.assertEqual(sample_rule["defaultConfiguration"]["level"], "error")

    def test_sarif_results_and_severity_mapping(self):
        """Verify findings are mapped to SARIF results with correct levels and normalized URIs."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()
        doc = SARIFReporter.generate_dict(result)

        results = doc["runs"][0]["results"]
        self.assertGreater(len(results), 0)

        levels = {r["level"] for r in results}
        self.assertIn("error", levels)    # CRITICAL and HIGH
        self.assertIn("warning", levels)  # MEDIUM

        for item in results:
            self.assertIn("ruleId", item)
            self.assertIn("message", item)
            self.assertIn("locations", item)
            self.assertGreaterEqual(len(item["locations"]), 1)

            phys = item["locations"][0]["physicalLocation"]
            uri = phys["artifactLocation"]["uri"]
            # Cross-platform URI must not contain backslashes
            self.assertNotIn("\\", uri, f"SARIF URI '{uri}' contains Windows backslash")

            region = phys["region"]
            self.assertGreaterEqual(region["startLine"], 1)

    def test_sarif_secure_agent_produces_zero_results(self):
        """Verify clean secure agent produces zero SARIF violation results."""
        engine = ScanEngine(self.secure_dir)
        result = engine.run()
        doc = SARIFReporter.generate_dict(result)

        self.assertEqual(len(doc["runs"][0]["results"]), 0)

    def test_cli_sarif_output(self):
        """Verify CLI exports SARIF report via -f sarif."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir)
            exit_code = main(["scan", str(self.vulnerable_dir), "-f", "sarif", "-o", str(out_path), "-q"])
            self.assertEqual(exit_code, 1)  # Threshold failure

            sarif_file = out_path / "orvyen_report.sarif"
            self.assertTrue(sarif_file.exists())
            data = json.loads(sarif_file.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
