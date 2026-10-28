"""
Command line interface for Orvyen Agentic.
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

from orvyen import __version__
from orvyen.core.models import Severity
from orvyen.core.engine import ScanEngine
from orvyen.compliance.aibom import AIBOMCompiler
from orvyen.compliance.license_gate import is_valid_license
from orvyen.reporters.console import ConsoleReporter
from orvyen.reporters.json_reporter import JSONReporter
from orvyen.reporters.html_reporter import HTMLReporter
from orvyen.reporters.pdf_reporter import PDFReporter
from orvyen.reporters.sarif_reporter import SARIFReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orvyen-agentic",
        description="Static Security & Compliance Scanner for AI Agents (LangChain, LangGraph, CrewAI, MCP)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"orvyen-agentic v{__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan an agent codebase or MCP manifest")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target file or directory to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "html", "aibom", "pdf", "sarif", "all"],
        default="terminal",
        help="Output report format (default: terminal)",
    )
    scan_parser.add_argument(
        "-o", "--output-dir",
        default="./scan_results",
        help="Output directory for generated reports (default: ./scan_results)",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO",
        help="Minimum finding severity to report (default: INFO)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Failure threshold for CI/CD exit code 1 (default: HIGH)",
    )
    scan_parser.add_argument(
        "--aibom-only",
        action="store_true",
        help="Emit only the Agent Bill of Materials without rule finding logs",
    )
    scan_parser.add_argument(
        "--compact",
        action="store_true",
        help="Display findings in compact single-line format (like Ruff / ESLint)",
    )
    scan_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress terminal decoration and summary banners",
    )
    scan_parser.add_argument(
        "--license-key",
        default=None,
        metavar="KEY",
        help="Orvyen Pro license key (unlocks AIBOM Markdown clause mapping). Get one at orvyen.dev/pricing",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        # Default to scan if path is provided or scan current dir
        args.command = "scan"
        if not hasattr(args, "target"):
            args.target = "."
        if not hasattr(args, "format"):
            args.format = "terminal"
        if not hasattr(args, "output_dir"):
            args.output_dir = "./scan_results"
        if not hasattr(args, "min_severity"):
            args.min_severity = "INFO"
        if not hasattr(args, "fail_on"):
            args.fail_on = "HIGH"
        if not hasattr(args, "aibom_only"):
            args.aibom_only = False
        if not hasattr(args, "quiet"):
            args.quiet = False

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        return 2

    # Execute Scan
    engine = ScanEngine(target_path)
    result = engine.run()

    # Compile AIBOM
    result.aibom = AIBOMCompiler.compile(result)

    min_sev = Severity[args.min_severity]
    out_dir = Path(args.output_dir)

    # If user just wants AIBOM
    if args.aibom_only:
        license_key = getattr(args, "license_key", None)
        md_aibom = AIBOMCompiler.to_markdown(result.aibom, license_key=license_key)
        print(md_aibom)
        return 0

    # Format handling
    if args.format in ("terminal", "all"):
        if not args.quiet:
            is_compact = getattr(args, "compact", False)
            ConsoleReporter.print_result(result, min_severity=min_sev, compact=is_compact)

    if args.format in ("json", "all"):
        json_path = out_dir / "orvyen_report.json"
        JSONReporter.write_to_file(result, json_path)
        if not args.quiet and args.format != "terminal":
            print(f"[+] JSON report saved to: {json_path}")

    if args.format in ("html", "all"):
        html_path = out_dir / "orvyen_report.html"
        HTMLReporter.write_to_file(result, html_path)
        if not args.quiet and args.format != "terminal":
            print(f"[+] HTML dashboard saved to: {html_path}")

    if args.format in ("aibom", "all"):
        aibom_json_path = out_dir / "aibom.json"
        aibom_md_path = out_dir / "aibom.md"
        out_dir.mkdir(parents=True, exist_ok=True)
        import json
        aibom_json_path.write_text(json.dumps(result.aibom, indent=2), encoding="utf-8")
        license_key = getattr(args, "license_key", None)
        aibom_md_path.write_text(
            AIBOMCompiler.to_markdown(result.aibom, license_key=license_key),
            encoding="utf-8",
        )
        if not args.quiet and args.format != "terminal":
            print(f"[+] AIBOM artifacts saved to: {out_dir}")

    if args.format in ("sarif", "all"):
        sarif_path = out_dir / "orvyen_report.sarif"
        SARIFReporter.write_to_file(result, sarif_path)
        if not args.quiet and args.format != "terminal":
            print(f"[+] SARIF 2.1.0 report saved to: {sarif_path}")

    if args.format == "pdf":
        license_key = getattr(args, "license_key", None)
        if not is_valid_license(license_key):
            print("Requires license: orvyen.dev/pricing", file=sys.stderr)
            return 1
        pdf_path = out_dir / "orvyen_report.pdf"
        PDFReporter.write_to_file(result, pdf_path, license_key=license_key)
        if not args.quiet:
            print(f"[+] PDF audit report saved to: {pdf_path}")
    elif args.format == "all":
        license_key = getattr(args, "license_key", None)
        if is_valid_license(license_key):
            pdf_path = out_dir / "orvyen_report.pdf"
            PDFReporter.write_to_file(result, pdf_path, license_key=license_key)
            if not args.quiet:
                print(f"[+] PDF audit report saved to: {pdf_path}")
        elif not args.quiet:
            print("[!] PDF audit report skipped (Requires license: orvyen.dev/pricing)")

    # Check failure gate
    if args.fail_on != "NONE":
        fail_threshold = Severity[args.fail_on]
        blocking_findings = [f for f in result.findings if f.severity >= fail_threshold]
        if blocking_findings:
            if not args.quiet:
                print(
                    f"\033[31m\033[1mScan FAILED: {len(blocking_findings)} violation(s) "
                    f"at or above '{args.fail_on}' threshold.\033[0m",
                    file=sys.stderr,
                )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
