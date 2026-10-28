"""
High-performance, tier-1 developer CLI console reporter for Orvyen Agentic.
Engineered to the visual standards of tools like Ruff, Cargo, Snyk, and Biome.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

from orvyen import __version__
from orvyen.core.models import ScanResult, Severity, Finding
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator


# Terminal styling primitives
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"

# Text Colors
RED = "\033[38;5;196m" if os.environ.get("COLORTERM") else "\033[31m"
LIGHT_RED = "\033[38;5;203m" if os.environ.get("COLORTERM") else "\033[91m"
GREEN = "\033[38;5;40m" if os.environ.get("COLORTERM") else "\033[32m"
YELLOW = "\033[38;5;214m" if os.environ.get("COLORTERM") else "\033[33m"
BLUE = "\033[38;5;75m" if os.environ.get("COLORTERM") else "\033[34m"
CYAN = "\033[38;5;44m" if os.environ.get("COLORTERM") else "\033[36m"
PURPLE = "\033[38;5;141m" if os.environ.get("COLORTERM") else "\033[35m"
WHITE = "\033[38;5;255m" if os.environ.get("COLORTERM") else "\033[97m"
GRAY = "\033[38;5;244m" if os.environ.get("COLORTERM") else "\033[90m"

# Background badges
BG_RED = "\033[48;5;196m\033[38;5;255m" if os.environ.get("COLORTERM") else "\033[41m\033[37m"
BG_ORANGE = "\033[48;5;202m\033[38;5;255m" if os.environ.get("COLORTERM") else "\033[43m\033[30m"
BG_YELLOW = "\033[48;5;220m\033[38;5;232m" if os.environ.get("COLORTERM") else "\033[43m\033[30m"
BG_BLUE = "\033[48;5;33m\033[38;5;255m" if os.environ.get("COLORTERM") else "\033[44m\033[37m"
BG_GREEN = "\033[48;5;34m\033[38;5;255m" if os.environ.get("COLORTERM") else "\033[42m\033[37m"


def _can_utf8() -> bool:
    """Check if stdout can safely render UTF-8 box drawing."""
    encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    return "utf" in encoding.lower()


class ConsoleReporter:
    """Renders sleek, enterprise-grade terminal output for security scans."""

    @classmethod
    def print_result(
        cls,
        result: ScanResult,
        min_severity: Severity = Severity.INFO,
        compact: bool = False,
    ) -> None:
        utf8 = _can_utf8()

        # 1. Sleek Brand Header
        cls._print_header(result, utf8)

        filtered = [f for f in result.findings if f.severity >= min_severity]

        # 2. Main Findings Body
        if not filtered:
            cls._print_clean_banner(utf8)
        else:
            if compact:
                cls._print_compact_findings(filtered, utf8)
            else:
                cls._print_detailed_findings(filtered, utf8)

        # 3. Executive Metrics & Governance Summary
        cls._print_summary_card(result, utf8)

    @classmethod
    def _print_header(cls, result: ScanResult, utf8: bool) -> None:
        bolt = "⚡" if utf8 else "*"
        bullet = "•" if utf8 else "-"
        print()
        print(
            f"{CYAN}{BOLD}{bolt} orvyen-agentic{RESET} {GRAY}v{__version__}{RESET} "
            f"{DIM}{bullet}{RESET} {WHITE}AI Agent Static Security & Compliance Scanner{RESET}"
        )
        try:
            rel_target = str(Path(result.target_path).relative_to(Path.cwd()))
            rel_target = f"./{rel_target}" if not rel_target.startswith(".") else rel_target
        except Exception:
            rel_target = result.target_path

        duration_sec = result.duration_ms / 1000
        timing_str = f"{result.duration_ms:.1f}ms" if result.duration_ms < 1000 else f"{duration_sec:.2f}s"

        print(
            f"{GRAY}Target:{RESET} {WHITE}{rel_target}{RESET}  "
            f"{GRAY}|  Files scanned:{RESET} {WHITE}{result.files_scanned}{RESET}  "
            f"{GRAY}|  Time:{RESET} {GREEN}{timing_str}{RESET}"
        )
        print()

    @classmethod
    def _print_clean_banner(cls, utf8: bool) -> None:
        check = "✔" if utf8 else "[PASS]"
        print(f"  {GREEN}{BOLD}{check} All clear!{RESET} {WHITE}No security vulnerabilities or policy violations detected.{RESET}")
        print(f"  {GRAY}All agent graphs, tools, prompts, and MCP gateways adhere to baseline policies.{RESET}")
        print()

    @classmethod
    def _print_detailed_findings(cls, findings: List[Finding], utf8: bool) -> None:
        # Group by file path for clarity
        findings_by_file: Dict[str, List[Finding]] = {}
        for f in findings:
            findings_by_file.setdefault(f.file_path, []).append(f)

        pipe = "│" if utf8 else "|"
        arrow = "-->" if utf8 else "-->"
        bullet = "•" if utf8 else "-"

        for file_path, file_findings in findings_by_file.items():
            try:
                rel_path = str(Path(file_path).relative_to(Path.cwd()))
            except Exception:
                rel_path = file_path

            for f in file_findings:
                cls._print_finding_card(f, rel_path, utf8)

    @classmethod
    def _print_finding_card(cls, f: Finding, rel_path: str, utf8: bool) -> None:
        pipe = "│" if utf8 else "|"
        bullet = "•" if utf8 else "-"
        cross = "✖" if utf8 else "[X]"
        arrow = "-->" if utf8 else "-->"

        sev = f.severity
        if sev == Severity.CRITICAL:
            sev_badge = f"{BG_RED}{BOLD} CRITICAL {RESET}"
            icon_color = RED
        elif sev == Severity.HIGH:
            sev_badge = f"{BG_ORANGE}{BOLD} HIGH {RESET}"
            icon_color = LIGHT_RED
        elif sev == Severity.MEDIUM:
            sev_badge = f"{BG_YELLOW}{BOLD} MEDIUM {RESET}"
            icon_color = YELLOW
        elif sev == Severity.LOW:
            sev_badge = f"{CYAN}{BOLD} LOW {RESET}"
            icon_color = CYAN
        else:
            sev_badge = f"{GRAY} INFO {RESET}"
            icon_color = GRAY

        # Title line
        print(f"{icon_color}{BOLD}{cross}{RESET} {sev_badge} {BOLD}{WHITE}{f.rule_id}{RESET} {GRAY}{bullet}{RESET} {BOLD}{f.rule_title}{RESET}")
        # Clickable location anchor (compatible with VS Code / JetBrains / Windows Terminal)
        print(f"  {GRAY}{arrow}{RESET} {UNDERLINE}{WHITE}{rel_path}:{f.line_number}:{f.column}{RESET}")
        print(f"  {GRAY}{pipe}{RESET}")

        # Code snippet block with line number gutter
        if f.code_snippet:
            lines = f.code_snippet.strip().splitlines()
            start_lineno = max(1, f.line_number - (len(lines) // 2))
            for offset, line_text in enumerate(lines[:5]):
                curr_no = start_lineno + offset
                is_target_line = (curr_no == f.line_number) or (offset == 0 and len(lines) == 1)
                gutter_color = RED if is_target_line else GRAY
                line_color = WHITE if is_target_line else GRAY
                mark = f"{icon_color}>{RESET}" if is_target_line else " "
                print(f"{mark} {gutter_color}{curr_no:>4} {pipe}{RESET} {line_color}{line_text}{RESET}")

            # Highlight caret underline
            print(f"    {GRAY}     {pipe}{RESET} {icon_color}{BOLD}{' ' * max(0, f.column - 1)}^^^^^^^^ {f.message}{RESET}")
        else:
            print(f"    {GRAY}     {pipe}{RESET} {WHITE}{f.message}{RESET}")

        print(f"  {GRAY}{pipe}{RESET}")
        print(f"  {GRAY}= Standards:{RESET}  {PURPLE}{BOLD}{f.owasp_id}{RESET} {GRAY}{bullet}{RESET} {BLUE}{f.imda_pillar}{RESET}")
        print(f"  {GRAY}= Fix:{RESET}        {GREEN}{f.remediation}{RESET}")
        print()

    @classmethod
    def _print_compact_findings(cls, findings: List[Finding], utf8: bool) -> None:
        bullet = "•" if utf8 else "-"
        for f in findings:
            try:
                rel_path = str(Path(f.file_path).relative_to(Path.cwd()))
            except Exception:
                rel_path = f.file_path

            sev = f.severity
            sev_color = RED if sev in (Severity.CRITICAL, Severity.HIGH) else (YELLOW if sev == Severity.MEDIUM else CYAN)
            print(
                f"{GRAY}{rel_path}:{f.line_number}:{f.column}{RESET} "
                f"{sev_color}{BOLD}{sev.value:<8}{RESET} "
                f"{WHITE}{BOLD}{f.rule_id}{RESET} "
                f"{GRAY}{bullet}{RESET} {f.message}"
            )
        print()

    @classmethod
    def _print_summary_card(cls, result: ScanResult, utf8: bool) -> None:
        imda = IMDAComplianceEvaluator.evaluate(result.findings)
        owasp = OWASPComplianceEvaluator.evaluate(result.findings)

        score = result.security_score
        if score >= 85:
            score_color = GREEN
            score_grade = "HEALTHY"
        elif score >= 60:
            score_color = YELLOW
            score_grade = "RISK DETECTED"
        else:
            score_color = RED
            score_grade = "HIGH VULNERABILITY"

        tl = "╭" if utf8 else "+"
        tr = "╮" if utf8 else "+"
        bl = "╰" if utf8 else "+"
        br = "╯" if utf8 else "+"
        h = "─" if utf8 else "-"
        v = "│" if utf8 else "|"
        bullet = "•" if utf8 else "-"

        width = 68
        title = " EXECUTIVE COMPLIANCE & RISK SUMMARY "
        left_pad = (width - len(title)) // 2
        right_pad = width - len(title) - left_pad

        print(f"{CYAN}{tl}{h * left_pad}{BOLD}{WHITE}{title}{RESET}{CYAN}{h * right_pad}{tr}{RESET}")
        
        # Row 1: Security Score Gauge
        score_line = f"  Security Score:       {score_color}{BOLD}{score:>3}/100{RESET}  {score_color}[{score_grade}]{RESET}"
        cls._print_card_row(score_line, width, v, utf8)

        # Row 2: Findings Count breakdown
        crit = f"{RED}{BOLD}{result.critical_count} Critical{RESET}"
        high = f"{LIGHT_RED}{BOLD}{result.high_count} High{RESET}"
        med = f"{YELLOW}{result.medium_count} Med{RESET}"
        low = f"{CYAN}{result.low_count} Low{RESET}"
        findings_line = f"  Violations Found:     {crit} {GRAY}{bullet}{RESET} {high} {GRAY}{bullet}{RESET} {med} {GRAY}{bullet}{RESET} {low}"
        cls._print_card_row(findings_line, width, v, utf8)

        # Row 3: Inventory summary
        exec_count = sum(1 for t in result.tools if t.privilege.value in ("EXECUTE", "ADMIN"))
        inventory_line = f"  Asset Inventory:      {WHITE}{len(result.tools)} Tools{RESET} ({RED}{exec_count} High-Privilege{RESET}) {GRAY}{bullet}{RESET} {WHITE}{len(result.mcp_servers)} MCP Gateways{RESET}"
        cls._print_card_row(inventory_line, width, v, utf8)

        # Row 4: Singapore IMDA Status
        imda_status = imda.get("overall_status")
        imda_color = GREEN if imda_status == "COMPLIANT" else RED
        imda_line = f"  Singapore IMDA:       {imda_color}{BOLD}{imda_status:<14}{RESET} ({imda.get('score_percentage')}% aligned to 4 Pillars)"
        cls._print_card_row(imda_line, width, v, utf8)

        # Row 5: OWASP LLM Status
        owasp_status = owasp.get("overall_status")
        owasp_color = GREEN if owasp_status == "PASS" else RED
        owasp_line = f"  OWASP LLM Top 10:     {owasp_color}{BOLD}{owasp_status:<14}{RESET} ({owasp.get('score_percentage')}% category pass rate)"
        cls._print_card_row(owasp_line, width, v, utf8)

        print(f"{CYAN}{bl}{h * width}{br}{RESET}")
        print()

    @classmethod
    def _print_card_row(cls, content_with_ansi: str, width: int, v: str, utf8: bool) -> None:
        """Strip ANSI escapes to calculate visual character length and pad to exact width."""
        import re
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        plain_len = len(ansi_escape.sub("", content_with_ansi))
        pad = max(0, width - plain_len)
        print(f"{CYAN}{v}{RESET}{content_with_ansi}{' ' * pad}{CYAN}{v}{RESET}")
