"""
Command line interface for Orvyen Agentic.
"""

from __future__ import annotations
import argparse
import os
import shutil
import sys
from pathlib import Path

from orvyen import __version__
from orvyen.core.models import Severity
from orvyen.core.engine import ScanEngine
from orvyen.compliance.aibom import AIBOMCompiler
from orvyen.compliance.license_gate import is_valid_license
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator
from orvyen.reporters.console import ConsoleReporter, InteractivePrompt
from orvyen.reporters.json_reporter import JSONReporter
from orvyen.reporters.html_reporter import HTMLReporter
from orvyen.reporters.pdf_reporter import PDFReporter
from orvyen.reporters.sarif_reporter import SARIFReporter

# Terminal styling primitives
from orvyen.reporters.console import (
    fg, bg, WHITE, GRAY_MUTED, GRAY_DARK, GRAY_LIGHT,
    GREEN_ACCENT, CYAN_ACCENT, RED_ACCENT, AMBER_ACCENT,
    RESET, BOLD, DIM,
)

CYAN = CYAN_ACCENT
GREEN = GREEN_ACCENT
RED = RED_ACCENT
GRAY = GRAY_MUTED
YELLOW = AMBER_ACCENT


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
        "--fancy",
        action="store_true",
        help="Display Claude Code-style interactive terminal UI with block art logo and autocomplete menu",
    )
    scan_parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        default=None,
        help="Keep session running in interactive mode with command prompt and keyboard shortcuts",
    )
    scan_parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Disable interactive mode and exit immediately after scan",
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


def interactive_loop(
    initial_target: Path,
    min_sev: Severity,
    is_compact: bool,
    is_fancy: bool,
    license_key: str | None = None,
) -> int:
    """Keeps the user in the interactive terminal session with live in-box prompt and dropdown."""
    curr_target = initial_target

    while True:
        try:
            if is_fancy and sys.stdin.isatty():
                raw = InteractivePrompt.ask(utf8=True)
            else:
                raw = input(f"  {GRAY_MUTED}>{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{GRAY_MUTED}Exiting Orvyen Agentic. Goodbye!{RESET}\n")
            return 0

        cmd = raw.lower()
        if cmd in ("exit", "quit", "q", "/exit", ":q"):
            print(f"\n{GRAY_MUTED}Exiting Orvyen Agentic. Goodbye!{RESET}\n")
            return 0

        elif cmd in ("", "/scan", "scan") or cmd.startswith(("/scan ", "scan ")):
            parts = raw.split(maxsplit=1)
            if len(parts) > 1 and parts[1].strip():
                new_target = Path(parts[1].strip())
                if new_target.exists():
                    curr_target = new_target
                else:
                    print(f"  {RED_ACCENT}Error: Path '{parts[1].strip()}' does not exist.{RESET}")
                    continue

            if is_fancy:
                os.system("cls" if os.name == "nt" else "clear")

            engine = ScanEngine(curr_target)
            res = engine.run()
            res.aibom = AIBOMCompiler.compile(res)
            ConsoleReporter.print_result(res, min_severity=min_sev, compact=is_compact, fancy=is_fancy)

        elif cmd in ("/secure", "secure"):
            if is_fancy:
                os.system("cls" if os.name == "nt" else "clear")
            curr_target = Path("tests/fixtures/secure_agent")
            if not curr_target.exists():
                curr_target = Path(__file__).parent.parent / "tests" / "fixtures" / "secure_agent"
            engine = ScanEngine(curr_target)
            res = engine.run()
            res.aibom = AIBOMCompiler.compile(res)
            ConsoleReporter.print_result(res, min_severity=min_sev, compact=is_compact, fancy=is_fancy)

        elif cmd in ("/vulnerable", "vulnerable"):
            if is_fancy:
                os.system("cls" if os.name == "nt" else "clear")
            curr_target = Path("tests/fixtures/vulnerable_agent")
            if not curr_target.exists():
                curr_target = Path(__file__).parent.parent / "tests" / "fixtures" / "vulnerable_agent"
            engine = ScanEngine(curr_target)
            res = engine.run()
            res.aibom = AIBOMCompiler.compile(res)
            ConsoleReporter.print_result(res, min_severity=min_sev, compact=is_compact, fancy=is_fancy)

        elif cmd in ("/aibom", "aibom"):
            engine = ScanEngine(curr_target)
            res = engine.run()
            res.aibom = AIBOMCompiler.compile(res)
            ConsoleReporter.print_aibom(res.aibom, utf8=is_fancy)

        elif cmd in ("/compliance", "compliance"):
            engine = ScanEngine(curr_target)
            res = engine.run()
            imda = IMDAComplianceEvaluator.evaluate(res.findings)
            owasp = OWASPComplianceEvaluator.evaluate(res.findings)
            ConsoleReporter.print_compliance(imda, owasp, utf8=is_fancy)

        elif cmd in ("/help", "help"):
            ConsoleReporter.print_help(utf8=is_fancy)

        elif cmd in ("/clear", "clear", "cls"):
            os.system("cls" if os.name == "nt" else "clear")
            ConsoleReporter.print_header(None, fancy=is_fancy)

        else:
            potential = Path(raw)
            if potential.exists():
                curr_target = potential
                if is_fancy:
                    os.system("cls" if os.name == "nt" else "clear")
                engine = ScanEngine(curr_target)
                res = engine.run()
                res.aibom = AIBOMCompiler.compile(res)
                ConsoleReporter.print_result(res, min_severity=min_sev, compact=is_compact, fancy=is_fancy)
            else:
                print(f"  {YELLOW}Unknown command '{raw}'. Type /help for available commands or press Ctrl+C to exit.{RESET}")


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
        if not hasattr(args, "compact"):
            args.compact = False
        if not hasattr(args, "fancy"):
            args.fancy = False
        if not hasattr(args, "interactive"):
            args.interactive = None
        if not hasattr(args, "no_interactive"):
            args.no_interactive = False
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

    is_compact = getattr(args, "compact", False)
    is_fancy = getattr(args, "fancy", False) or (
        sys.stdout.isatty() and not is_compact
    )

    # Determine whether to enter interactive mode
    if getattr(args, "no_interactive", False):
        is_interactive = False
    elif getattr(args, "interactive", False):
        is_interactive = True
    else:
        is_interactive = (
            sys.stdin.isatty()
            and sys.stdout.isatty()
            and not args.quiet
            and args.format == "terminal"
            and not os.environ.get("CI")
            and not os.environ.get("ORVYEN_NO_INTERACTIVE")
        )

    # Format handling
    if args.format in ("terminal", "all"):
        if not args.quiet:
            if is_fancy and is_interactive:
                os.system("cls" if os.name == "nt" else "clear")
            ConsoleReporter.print_result(
                result,
                min_severity=min_sev,
                compact=is_compact,
                fancy=is_fancy,
            )

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
            sys.stdout.flush()
            if not args.quiet:
                print(
                    f"\033[31m\033[1mScan FAILED: {len(blocking_findings)} violation(s) "
                    f"at or above '{args.fail_on}' threshold.\033[0m",
                    file=sys.stderr,
                )
            if not is_interactive:
                return 1

    # Enter interactive session loop if enabled
    if is_interactive:
        return interactive_loop(
            initial_target=target_path,
            min_sev=min_sev,
            is_compact=is_compact,
            is_fancy=is_fancy,
            license_key=getattr(args, "license_key", None),
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
