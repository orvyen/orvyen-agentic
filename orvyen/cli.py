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
from orvyen.core.models import Severity, ScanResult
from orvyen.core.engine import ScanEngine
from orvyen.compliance.aibom import AIBOMCompiler
from orvyen.compliance.license_gate import is_valid_license
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator
from orvyen.reporters.json_reporter import JSONReporter
from orvyen.reporters.html_reporter import HTMLReporter
from orvyen.reporters.pdf_reporter import PDFReporter
from orvyen.reporters.sarif_reporter import SARIFReporter
from orvyen.reporters.console import (
    ConsoleReporter,
    InteractivePrompt,
    run_spinner_phase,
    fg, bg, WHITE, GRAY_MUTED, GRAY_DARK, GRAY_LIGHT,
    GREEN_ACCENT, CYAN_ACCENT, RED_ACCENT, AMBER_ACCENT,
    PRIMARY, DIM, FAINT, GREEN, RED, ACCENT,
    RESET, BOLD,
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

    parser.add_argument(
        "--no-anim",
        action="store_true",
        help="Disable terminal animations and spinners (run phases as plain static text)",
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
        choices=["terminal", "json", "sarif", "aibom", "html", "pdf", "all"],
        default="terminal",
        type=str.lower,
        help="Output report format (default: terminal; CI/CD formats: json, sarif, aibom; Pro: pdf, html)",
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
        type=str.upper,
        help="Minimum finding severity to report (default: INFO)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        type=str.upper,
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
        "--no-anim",
        action="store_true",
        help="Disable terminal animations and spinners (run phases as plain static text)",
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
        help="Orvyen Pro license key (unlocks AIBOM Markdown clause mapping). Get one at orvyen.com/pricing",
    )

    return parser


def execute_phased_scan(
    target_path: Path,
    no_anim: bool = False,
    quiet: bool = False,
    is_interactive: bool = False,
    print_header: bool = True,
) -> tuple[ScanResult, Dict[str, Any], Dict[str, Any]]:
    """
    Executes scan across 3 minimal Claude Code-style phases:
    1. scanning {N} files
    2. evaluating 12 rules
    3. checking compliance
    Returns (result, imda, owasp).
    """
    engine = ScanEngine(target_path)
    ctx, all_files = engine.prepare_context()
    num_files = len(all_files)

    # Print header on first launch or when target changes (controlled by caller)
    if not quiet and print_header and not ConsoleReporter._header_printed:
        ConsoleReporter.print_header(target_path=str(target_path), files_count=num_files)

    # Print prompt line (always, so user sees which command ran)
    if not quiet:
        ConsoleReporter.print_prompt("/scan")

    # Phase 1: scanning files
    def p1_action():
        engine.parse_files(ctx, all_files)
        return ctx

    if quiet:
        p1_action()
        t1 = 0.0
    else:
        _, t1 = run_spinner_phase(
            f"scanning {num_files} files",
            p1_action,
            no_anim=no_anim,
            min_visual_ms=600,
        )

    # Phase 2: evaluating 12 rules
    def p2_action():
        return engine.evaluate_rules(ctx)

    if quiet:
        all_findings = p2_action()
        t2 = 0.0
    else:
        all_findings, t2 = run_spinner_phase(
            "evaluating 12 rules",
            p2_action,
            no_anim=no_anim,
            min_visual_ms=800,
        )

    # Phase 3: checking compliance
    def p3_action():
        imda = IMDAComplianceEvaluator.evaluate(all_findings)
        owasp = OWASPComplianceEvaluator.evaluate(all_findings)
        return imda, owasp

    if quiet:
        (imda, owasp) = p3_action()
        t3 = 0.0
    else:
        (imda, owasp), t3 = run_spinner_phase(
            "checking compliance",
            p3_action,
            no_anim=no_anim,
            min_visual_ms=450,
        )

    total_dur_ms = t1 + t2 + t3
    result = ScanResult(
        target_path=str(engine.target_path),
        files_scanned=num_files,
        duration_ms=total_dur_ms,
        findings=all_findings,
        tools=ctx.tools,
        agents=ctx.agents,
        mcp_servers=ctx.mcp_servers,
        edges=ctx.edges,
        phase_timings={
            "scanning_files": t1,
            "evaluating_rules": t2,
            "checking_compliance": t3,
        },
    )
    result.aibom = AIBOMCompiler.compile(result)

    return result, imda, owasp


def interactive_loop(
    initial_target: Path,
    min_sev: Severity,
    is_compact: bool = False,
    is_fancy: bool = True,
    license_key: str | None = None,
    no_anim: bool = False,
) -> int:
    """Keeps the user in the interactive terminal session with live minimal slash menu."""
    curr_target = initial_target

    while True:
        try:
            if sys.stdin.isatty():
                raw = InteractivePrompt.ask(initial_text="/scan", utf8=True)
            else:
                raw = input(f"  {DIM}›{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{DIM}cancelled{RESET}\n")
            return 130

        cmd = raw.lower().strip()
        if cmd in ("exit", "quit", "q", "/exit", ":q"):
            return 0

        elif cmd in ("", "/scan", "scan") or cmd.startswith(("/scan ", "scan ")):
            parts = raw.split(maxsplit=1)
            if len(parts) > 1 and parts[1].strip():
                new_target = Path(parts[1].strip())
                if new_target.exists():
                    curr_target = new_target
                    # New target — reset header so it shows new path
                    ConsoleReporter._header_printed = False
                else:
                    print(f"  {RED}Error: Path '{parts[1].strip()}' does not exist.{RESET}\n")
                    continue

            result, imda, owasp = execute_phased_scan(
                curr_target,
                no_anim=no_anim,
                quiet=False,
                is_interactive=True,
                print_header=True,
            )
            ConsoleReporter.print_verdict(result, min_severity=min_sev)
            ConsoleReporter.print_summary(result, imda, owasp, no_anim=no_anim)
            ConsoleReporter.print_next_step(result, command_type="scan")

        elif cmd in ("/secure", "secure"):
            fixture = Path("tests/fixtures/secure_agent")
            if not fixture.exists():
                fixture = Path(__file__).parent.parent / "tests" / "fixtures" / "secure_agent"
            if not fixture.exists():
                print(f"  {RED}Error: Fixture 'tests/fixtures/secure_agent' not found.{RESET}\n")
                continue
            curr_target = fixture
            # Reset header so it re-prints with the new target path
            ConsoleReporter._header_printed = False
            result, imda, owasp = execute_phased_scan(
                curr_target,
                no_anim=no_anim,
                quiet=False,
                is_interactive=True,
                print_header=True,
            )
            ConsoleReporter.print_verdict(result, min_severity=min_sev)
            ConsoleReporter.print_summary(result, imda, owasp, no_anim=no_anim)
            ConsoleReporter.print_next_step(result, command_type="scan")

        elif cmd in ("/vulnerable", "vulnerable"):
            fixture = Path("tests/fixtures/vulnerable_agent")
            if not fixture.exists():
                fixture = Path(__file__).parent.parent / "tests" / "fixtures" / "vulnerable_agent"
            if not fixture.exists():
                print(f"  {RED}Error: Fixture 'tests/fixtures/vulnerable_agent' not found.{RESET}\n")
                continue
            curr_target = fixture
            # Reset header so it re-prints with the new target path
            ConsoleReporter._header_printed = False
            result, imda, owasp = execute_phased_scan(
                curr_target,
                no_anim=no_anim,
                quiet=False,
                is_interactive=True,
                print_header=True,
            )
            ConsoleReporter.print_verdict(result, min_severity=min_sev)
            ConsoleReporter.print_summary(result, imda, owasp, no_anim=no_anim)
            ConsoleReporter.print_next_step(result, command_type="scan")

        elif cmd in ("/abom", "abom", "/aibom", "aibom"):
            engine = ScanEngine(curr_target)
            res = engine.run()
            res.aibom = AIBOMCompiler.compile(res)
            ConsoleReporter.print_aibom(res.aibom)

        elif cmd in ("/compliance", "compliance"):
            engine = ScanEngine(curr_target)
            res = engine.run()
            imda = IMDAComplianceEvaluator.evaluate(res.findings)
            owasp = OWASPComplianceEvaluator.evaluate(res.findings)
            ConsoleReporter.print_compliance(imda, owasp)

        elif cmd in ("/help", "help"):
            ConsoleReporter.print_help()

        elif cmd in ("/clear", "clear", "cls"):
            os.system("cls" if os.name == "nt" else "clear")
            ConsoleReporter._header_printed = False
            ConsoleReporter.print_header(target_path=str(curr_target))

        else:
            potential = Path(raw)
            if potential.exists():
                curr_target = potential
                ConsoleReporter._header_printed = False
                result, imda, owasp = execute_phased_scan(
                    curr_target,
                    no_anim=no_anim,
                    quiet=False,
                    is_interactive=True,
                    print_header=True,
                )
                ConsoleReporter.print_verdict(result, min_severity=min_sev)
                ConsoleReporter.print_summary(result, imda, owasp, no_anim=no_anim)
                ConsoleReporter.print_next_step(result, command_type="scan")
            else:
                print(f"  {DIM}Unknown command '{raw}'. Type /help for available commands or press Ctrl+C to exit.{RESET}\n")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    raw_argv = list(argv if argv is not None else sys.argv[1:])
    if raw_argv and raw_argv[0] not in ("scan", "-h", "--help", "-v", "--version"):
        raw_argv.insert(0, "scan")

    parser = build_parser()
    args = parser.parse_args(raw_argv)

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
        if not hasattr(args, "no_anim"):
            args.no_anim = False
        if not hasattr(args, "quiet"):
            args.quiet = False

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        return 2

    no_anim = (
        getattr(args, "no_anim", False)
        or not sys.stdout.isatty()
        or os.environ.get("CI") == "true"
        or os.environ.get("TERM") == "dumb"
        or "NO_COLOR" in os.environ
    )

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
            and not getattr(args, "quiet", False)
            and getattr(args, "format", "terminal") == "terminal"
            and not os.environ.get("CI")
            and not os.environ.get("ORVYEN_NO_INTERACTIVE")
        )

    min_sev = Severity[args.min_severity]
    out_dir = Path(args.output_dir)

    # Clear screen on startup if interactive
    if is_interactive and sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")

    # Execute Scan
    if args.format in ("terminal", "all") and not args.quiet:
        result, imda, owasp = execute_phased_scan(
            target_path,
            no_anim=no_anim,
            quiet=False,
            is_interactive=is_interactive,
        )
        ConsoleReporter.print_verdict(result, min_severity=min_sev)
        ConsoleReporter.print_summary(result, imda, owasp, no_anim=no_anim)
        ConsoleReporter.print_next_step(result, command_type="scan")
    else:
        engine = ScanEngine(target_path)
        result = engine.run()
        result.aibom = AIBOMCompiler.compile(result)

    # If user just wants AIBOM
    if args.aibom_only:
        license_key = getattr(args, "license_key", None)
        md_aibom = AIBOMCompiler.to_markdown(result.aibom, license_key=license_key)
        print(md_aibom)
        return 0

    if args.format != "terminal":
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Error: Unable to create output directory '{out_dir}': {e}", file=sys.stderr)
            return 2

    try:
        if args.format in ("json", "all"):
            json_path = out_dir / "orvyen_report.json"
            JSONReporter.write_to_file(result, json_path)
            if not args.quiet and args.format != "terminal":
                print(f"[+] JSON report saved to: {json_path}")

        if args.format in ("sarif", "all"):
            sarif_path = out_dir / "orvyen_report.sarif"
            SARIFReporter.write_to_file(result, sarif_path)
            if not args.quiet and args.format != "terminal":
                print(f"[+] SARIF 2.1.0 report saved to: {sarif_path}")

        if args.format in ("aibom", "all"):
            aibom_json_path = out_dir / "aibom.json"
            aibom_md_path = out_dir / "aibom.md"
            import json
            aibom_json_path.write_text(json.dumps(result.aibom, indent=2), encoding="utf-8")
            license_key = getattr(args, "license_key", None)
            aibom_md_path.write_text(
                AIBOMCompiler.to_markdown(result.aibom, license_key=license_key),
                encoding="utf-8",
            )
            if not args.quiet and args.format != "terminal":
                print(f"[+] AIBOM artifacts saved to: {out_dir}")

        if args.format == "html":
            license_key = getattr(args, "license_key", None)
            if not is_valid_license(license_key):
                print("Requires license: orvyen.com/pricing", file=sys.stderr)
                return 1
            html_path = out_dir / "orvyen_report.html"
            HTMLReporter.write_to_file(result, html_path)
            if not args.quiet:
                print(f"[+] HTML dashboard saved to: {html_path}")

        if args.format == "pdf":
            license_key = getattr(args, "license_key", None)
            if not is_valid_license(license_key):
                print("Requires license: orvyen.com/pricing", file=sys.stderr)
                return 1
            pdf_path = out_dir / "orvyen_report.pdf"
            PDFReporter.write_to_file(result, pdf_path, license_key=license_key)
            if not args.quiet:
                print(f"[+] PDF audit report saved to: {pdf_path}")
    except Exception as e:
        print(f"Error: Failed to write report artifacts to '{out_dir}': {e}", file=sys.stderr)
        return 1

    # Check failure gate
    if args.fail_on != "NONE":
        fail_threshold = Severity[args.fail_on]
        blocking_findings = [f for f in result.findings if f.severity >= fail_threshold]
        if blocking_findings:
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
            no_anim=no_anim,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
