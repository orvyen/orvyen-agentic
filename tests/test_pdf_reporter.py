"""
Test suite for audit-ready PDF reporter and license gating.
"""

import hashlib
import hmac
import tempfile
import time
import unittest
from pathlib import Path

from orvyen.core.engine import ScanEngine
from orvyen.reporters.pdf_reporter import PDFReporter
from orvyen.compliance.license_gate import is_valid_license
from orvyen.cli import main


def _generate_valid_test_license() -> str:
    SALT = b"orvyen-license-v1"
    prefix = "OAG-PRO"
    digest = hmac.new(SALT, prefix.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{prefix}.{digest}"


class TestPDFReporter(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.vulnerable_dir = self.fixtures_dir / "vulnerable_agent"
        self.secure_dir = self.fixtures_dir / "secure_agent"
        self.valid_license = _generate_valid_test_license()

    def test_pdf_generation_requires_license(self):
        """Verify PDF generation fails with PermissionError without valid license."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        # No license key
        with self.assertRaises(PermissionError) as ctx:
            PDFReporter.generate(result, license_key=None)
        self.assertIn("Requires license: orvyen.dev/pricing", str(ctx.exception))

        # Invalid license key
        with self.assertRaises(PermissionError) as ctx:
            PDFReporter.generate(result, license_key="OAG-INVALID.1234567890abcdef")
        self.assertIn("Requires license: orvyen.dev/pricing", str(ctx.exception))

    def test_pdf_generation_with_valid_license(self):
        """Verify audit-ready PDF document is generated with cover, summary, AIBOM, and matrices."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        pdf_bytes = PDFReporter.generate(result, license_key=self.valid_license)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf_bytes.rstrip().endswith(b"%%EOF"))

        # Check required audit content
        self.assertIn(b"ORVYEN", pdf_bytes)
        self.assertIn(b"ORVYEN AGENTIC", pdf_bytes)
        self.assertIn(b"AI Agent Security & Regulatory Compliance Audit Report", pdf_bytes)
        self.assertIn(b"EXECUTIVE POSTURE SCORE", pdf_bytes)
        self.assertIn(b"AGENT BILL OF MATERIALS", pdf_bytes)
        self.assertIn(b"AIBOM", pdf_bytes)
        self.assertIn(b"SECURITY FINDINGS", pdf_bytes)
        self.assertIn(b"SINGAPORE IMDA", pdf_bytes)
        self.assertIn(b"OWASP", pdf_bytes)

    def test_pdf_generation_on_secure_agent(self):
        """Verify PDF generation on secure agent fixture."""
        engine = ScanEngine(self.secure_dir)
        result = engine.run()

        pdf_bytes = PDFReporter.generate(result, license_key=self.valid_license)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertIn(b"100 / 100", pdf_bytes)
        self.assertIn(b"ZERO SECURITY VIOLATIONS DETECTED", pdf_bytes)

    def test_pdf_generation_performance_under_500ms(self):
        """Verify PDF report generation completes in well under 500ms."""
        engine = ScanEngine(self.vulnerable_dir)
        result = engine.run()

        start = time.perf_counter()
        pdf_bytes = PDFReporter.generate(result, license_key=self.valid_license)
        duration_ms = (time.perf_counter() - start) * 1000

        self.assertLess(
            duration_ms,
            500.0,
            f"PDF generation took {duration_ms:.2f}ms, exceeding 500ms limit",
        )
        self.assertGreater(len(pdf_bytes), 1000)

    def test_cli_pdf_format_requires_license(self):
        """Verify CLI --format pdf requires license key or exits with error."""
        import io
        from unittest.mock import patch

        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = main(["scan", str(self.vulnerable_dir), "-f", "pdf", "-q"])

        self.assertEqual(exit_code, 1)
        err_output = stderr_capture.getvalue()
        self.assertIn("Requires license: orvyen.dev/pricing", err_output)

    def test_cli_pdf_format_succeeds_with_license(self):
        """Verify CLI --format pdf generates orvyen_report.pdf when valid license key is passed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir)
            exit_code = main([
                "scan",
                str(self.secure_dir),
                "-f", "pdf",
                "--license-key", self.valid_license,
                "-o", str(out_path),
                "-q",
            ])
            self.assertEqual(exit_code, 0)
            pdf_file = out_path / "orvyen_report.pdf"
            self.assertTrue(pdf_file.exists())
            content = pdf_file.read_bytes()
            self.assertTrue(content.startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
