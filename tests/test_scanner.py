"""
Comprehensive test suite for Orvyen Agentic static scanner v0.2.0.
"""

import json
import unittest
from pathlib import Path

from orvyen.core.engine import ScanEngine
from orvyen.compliance.aibom import AIBOMCompiler
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator
from orvyen.compliance.license_gate import is_valid_license
from orvyen.reporters.json_reporter import JSONReporter
from orvyen.reporters.html_reporter import HTMLReporter
from orvyen.cli import main


class TestOrvyenScanner(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.vulnerable_dir = self.fixtures_dir / "vulnerable_agent"
        self.secure_dir = self.fixtures_dir / "secure_agent"

    def test_vulnerable_agent_triggers_all_eight_rules(self):
        """Verify that the vulnerable agent fixture triggers every rule OAG-001 through OAG-008."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        triggered_rule_ids = {f.rule_id for f in result.findings}

        expected_rules = {
            "OAG-001",  # Tool over-permissioning (shell execution / drop table)
            "OAG-002",  # Prompt injection (f-string in SystemMessage)
            "OAG-003",  # Hardcoded secrets (.env and mcp_servers.json)
            "OAG-004",  # PII flow to external sync sink
            "OAG-005",  # Unbounded recursion (LangGraph cycle without limit)
            "OAG-006",  # Orphaned tools (legacy tool never bound)
            "OAG-007",  # Missing rate limits (CrewAI agent without max_iter)
            "OAG-008",  # Unaudited state mutations (database update without audit logging)
        }

        for rule_id in expected_rules:
            self.assertIn(
                rule_id,
                triggered_rule_ids,
                f"Rule {rule_id} was expected to trigger on vulnerable agent fixture but did not.",
            )

        # Confirm failure metrics
        self.assertGreater(result.critical_count, 0)
        self.assertGreater(result.high_count, 0)
        self.assertLess(result.security_score, 60)

    def test_vulnerable_agent_triggers_new_rules_009_to_012(self):
        """Verify OAG-009 through OAG-012 all fire on the vulnerable fixture."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        triggered_rule_ids = {f.rule_id for f in result.findings}

        new_rules = {
            "OAG-009",  # Insecure MCP transport (http:// URL in args)
            "OAG-010",  # Missing human-in-the-loop (ADMIN/EXECUTE tools, no interrupt)
            "OAG-011",  # Excessive tool chaining (9 tools > 5 limit)
            "OAG-012",  # Sensitive data exfiltration (PII params + HTTP POST sink)
        }

        for rule_id in new_rules:
            self.assertIn(
                rule_id,
                triggered_rule_ids,
                f"New rule {rule_id} was expected to trigger on vulnerable fixture but did not.",
            )

    def test_secure_agent_produces_clean_pass(self):
        """Verify that the secure agent fixture passes without high or critical violations."""
        engine = ScanEngine(self.secure_dir)
        result = engine.run()

        # No critical or high findings
        self.assertEqual(result.critical_count, 0)
        self.assertEqual(result.high_count, 0)

        # High security health score
        self.assertGreaterEqual(result.security_score, 85)

        # IMDA compliance should be 100%
        imda = IMDAComplianceEvaluator.evaluate(result.findings)
        self.assertEqual(imda["overall_status"], "COMPLIANT")
        self.assertEqual(imda["score_percentage"], 100)

        # OWASP LLM compliance should be PASS
        owasp = OWASPComplianceEvaluator.evaluate(result.findings)
        self.assertEqual(owasp["overall_status"], "PASS")

    def test_aibom_compiler(self):
        """Verify AIBOM compilation produces valid JSON schema and Markdown output."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        aibom = AIBOMCompiler.compile(result)
        self.assertEqual(aibom["spec_version"], "1.0.0")
        self.assertIn("tools", aibom)
        self.assertIn("compliance", aibom)
        self.assertIn("singapore_imda", aibom["compliance"])
        self.assertIn("owasp_llm_top10", aibom["compliance"])

        # Free-tier markdown (no license key) should have tool inventory
        md_free = AIBOMCompiler.to_markdown(aibom, license_key=None)
        self.assertIn("# Agent Bill of Materials (AIBOM)", md_free)
        self.assertIn("Tool Inventory", md_free)
        # Free tier should NOT contain full compliance clause tables
        self.assertIn("orvyen.com/pricing", md_free)

    def test_aibom_markdown_pro_with_valid_license(self):
        """Verify that a valid license key unlocks full IMDA/OWASP clause mapping in Markdown."""
        import hashlib
        import hmac as _hmac

        # Generate a valid key using the same logic as license_gate.py
        SALT = b"orvyen-license-v1"
        prefix = "OAG-PRO"
        digest = _hmac.new(SALT, prefix.encode(), hashlib.sha256).hexdigest()[:16]
        valid_key = f"{prefix}.{digest}"

        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()
        aibom = AIBOMCompiler.compile(result)

        md_pro = AIBOMCompiler.to_markdown(aibom, license_key=valid_key)
        self.assertIn("# Agent Bill of Materials (AIBOM)", md_pro)
        self.assertIn("Singapore IMDA Model AI Governance Framework", md_pro)
        self.assertIn("OWASP Top 10 for LLM Applications", md_pro)
        # Pro tier should NOT contain the upgrade prompt
        self.assertNotIn("orvyen.com/pricing", md_pro)

    def test_license_gate_validation(self):
        """Verify license gate accepts valid keys and rejects invalid/empty ones."""
        import hashlib
        import hmac as _hmac

        SALT = b"orvyen-license-v1"
        prefix = "OAG-PRO"
        digest = _hmac.new(SALT, prefix.encode(), hashlib.sha256).hexdigest()[:16]
        valid_key = f"{prefix}.{digest}"

        self.assertTrue(is_valid_license(valid_key))
        self.assertFalse(is_valid_license(None))
        self.assertFalse(is_valid_license(""))
        self.assertFalse(is_valid_license("OAG-PRO.000000000000000"))  # wrong digest
        self.assertFalse(is_valid_license("INVALID.format"))
        self.assertFalse(is_valid_license("nolicense"))

    def test_reporters_output(self):
        """Verify JSON and HTML report generation."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        # Test JSON reporter
        json_str = JSONReporter.generate(result)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["target_path"], str(self.vulnerable_dir.resolve()))
        self.assertIn("findings", parsed)

        # Test HTML reporter
        html_str = HTMLReporter.generate(result)
        self.assertIn("<!DOCTYPE html>", html_str)
        self.assertIn("ORVYEN AGENTIC", html_str)
        self.assertIn("Agent Bill of Materials (AIBOM)", html_str)

    def test_cli_exit_codes(self):
        """Verify CLI returns exit code 1 for vulnerable agent and 0 for secure agent."""
        # Vulnerable target should fail with exit code 1
        vuln_exit = main(["scan", str(self.vulnerable_dir), "--quiet", "--fail-on", "HIGH"])
        self.assertEqual(vuln_exit, 1)

        # Secure target should pass with exit code 0
        sec_exit = main(["scan", str(self.secure_dir), "--quiet", "--fail-on", "HIGH"])
        self.assertEqual(sec_exit, 0)

    def test_owasp_matrix_includes_new_rules(self):
        """Verify OWASP matrix now tracks LLM09 for OAG-009."""
        from orvyen.compliance.owasp_matrix import OWASP_LLM_ITEMS
        self.assertIn("LLM09", OWASP_LLM_ITEMS)
        self.assertIn("OAG-009", OWASP_LLM_ITEMS["LLM09"]["rules"])
        self.assertIn("OAG-012", OWASP_LLM_ITEMS["LLM02"]["rules"])
        self.assertIn("OAG-010", OWASP_LLM_ITEMS["LLM06"]["rules"])
        self.assertIn("OAG-011", OWASP_LLM_ITEMS["LLM06"]["rules"])

    def test_imda_matrix_includes_new_rules(self):
        """Verify IMDA matrix pillars include OAG-009 through OAG-012."""
        from orvyen.compliance.imda_matrix import IMDA_PILLARS
        pillar1_rules = IMDA_PILLARS["Pillar 1"]["rules"]
        pillar2_rules = IMDA_PILLARS["Pillar 2"]["rules"]
        pillar3_rules = IMDA_PILLARS["Pillar 3"]["rules"]

        self.assertIn("OAG-011", pillar1_rules)
        self.assertIn("OAG-010", pillar2_rules)
        self.assertIn("OAG-009", pillar3_rules)
        self.assertIn("OAG-012", pillar3_rules)

    def test_scan_performance_under_100ms(self):
        """Verify scan completes in under 100ms on both fixture sets."""
        import time

        for label, target in [("vulnerable", self.vulnerable_dir), ("secure", self.secure_dir)]:
            engine = ScanEngine(target)
            start = time.perf_counter()
            result = engine.run()
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.assertLess(
                elapsed_ms,
                100,
                f"{label} scan exceeded 100ms target: {elapsed_ms:.1f}ms",
            )
            self.assertLess(result.duration_ms, 100)


if __name__ == "__main__":
    unittest.main()

