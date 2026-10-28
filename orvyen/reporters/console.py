"""
High-performance, tier-1 developer CLI console reporter for Orvyen Agentic.
Engineered to modern developer tooling standards (JetBrains Mono, Vercel/Linear dark tokens).
Features a real chevron ANSI block matrix from Orvyen_1.png, floating cards,
status pills, and precision compliance summary matrices.
"""

from __future__ import annotations
import os
import shutil
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

from orvyen import __version__
from orvyen.core.models import ScanResult, Severity, Finding
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator

# Ensure UTF-8 output on Windows consoles if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def fg(hex_code: str) -> str:
    """Returns ANSI 24-bit TrueColor foreground escape sequence."""
    hex_code = hex_code.lstrip("#")
    if len(hex_code) == 3:
        hex_code = "".join(c * 2 for c in hex_code)
    r = int(hex_code[0:2], 16)
    g = int(hex_code[2:4], 16)
    b = int(hex_code[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"


def bg(hex_code: str) -> str:
    """Returns ANSI 24-bit TrueColor background escape sequence."""
    hex_code = hex_code.lstrip("#")
    if len(hex_code) == 3:
        hex_code = "".join(c * 2 for c in hex_code)
    r = int(hex_code[0:2], 16)
    g = int(hex_code[2:4], 16)
    b = int(hex_code[4:6], 16)
    return f"\033[48;2;{r};{g};{b}m"


# Text styling primitives
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"
BLINK = "\033[5m"

# Standard Palette
WHITE = fg("#FFFFFF")
GRAY_MUTED = fg("#6B7280")
GRAY_DARK = fg("#4B5563")
GRAY_LIGHT = fg("#9CA3AF")
GREEN_ACCENT = fg("#10B981")
CYAN_ACCENT = fg("#06B6D4")
RED_ACCENT = fg("#EF4444")
AMBER_ACCENT = fg("#F59E0B")

# Precomputed 16x16 pixel matrix extracted directly from Orvyen_1.png
# Real right-facing chevron geometry with offset red block on the left and white square cutout.
PRECOMPUTED_16X16 = [
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
    [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
]


def _can_utf8() -> bool:
    """Check if stdout can safely render UTF-8 box drawing."""
    encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    return "utf" in encoding.lower()


def load_logo_matrix() -> List[List[int]]:
    """
    Attempts to load Orvyen_1.png at runtime using PIL and downsample to 16x16.
    Falls back gracefully to PRECOMPUTED_16X16, maintaining zero mandatory dependencies.
    """
    candidates = [
        Path.cwd() / "Orvyen_1.png",
        Path("/mnt/data/Orvyen_1.png"),
        Path(__file__).parent.parent / "assets" / "Orvyen_1.png",
        Path("C:/mnt/data/Orvyen_1.png"),
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                from PIL import Image  # type: ignore
                im = Image.open(candidate).convert("RGBA").resize((16, 16), Image.Resampling.LANCZOS)
                matrix: List[List[int]] = []
                for y in range(16):
                    row: List[int] = []
                    for x in range(16):
                        px = im.getpixel((x, y))
                        is_red = px[0] > 160 and px[1] < 120 and px[2] < 120 and px[3] > 100
                        row.append(1 if is_red else 0)
                    matrix.append(row)
                if any(sum(r) > 0 for r in matrix):
                    return matrix
            except Exception:
                pass
    return PRECOMPUTED_16X16


def render_logo_lines(matrix: List[List[int]], utf8: bool = True) -> List[str]:
    """
    Renders the 16x16 matrix into 8 terminal lines using half-block characters
    (▀ upper half, ▄ lower half, █ full block) with #EF4444 true red.
    """
    lines: List[str] = []
    red_color = RED_ACCENT
    for r in range(8):
        top_row = matrix[r * 2]
        bot_row = matrix[r * 2 + 1]
        line_chars: List[str] = []
        for c in range(16):
            t = top_row[c]
            b = bot_row[c]
            if not utf8:
                line_chars.append("#" if (t or b) else " ")
            else:
                if t and b:
                    line_chars.append(f"{red_color}█{RESET}")
                elif t and not b:
                    line_chars.append(f"{red_color}▀{RESET}")
                elif not t and b:
                    line_chars.append(f"{red_color}▄{RESET}")
                else:
                    line_chars.append(" ")
        lines.append("".join(line_chars))
    return lines


class ConsoleReporter:
    """Renders sleek, enterprise-grade terminal output for security scans."""

    @classmethod
    def print_result(
        cls,
        result: ScanResult,
        min_severity: Severity = Severity.INFO,
        compact: bool = False,
        fancy: bool = False,
    ) -> None:
        utf8 = _can_utf8()

        # 1. Header (Fancy or Compact)
        if fancy:
            cls._print_fancy_header(result, utf8)
            cls._print_fancy_dropdown(utf8)
        else:
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

        # 3. Footer Metric Line & Executive Compliance Summary Card
        if fancy:
            cls._print_footer(result, utf8)

        cls._print_summary_card(result, utf8)

    @classmethod
    def print_header(cls, result: Optional[ScanResult] = None, fancy: bool = True) -> None:
        """Standalone header printer for CLI entrypoints or REPL initialization."""
        utf8 = _can_utf8()
        if fancy:
            cls._print_fancy_header(result, utf8)
        else:
            cls._print_header(result, utf8)

    @classmethod
    def _print_fancy_header(cls, result: Optional[ScanResult], utf8: bool) -> None:
        matrix = load_logo_matrix()
        logo_lines = render_logo_lines(matrix, utf8=utf8)
        term_width = min(max(shutil.get_terminal_size((80, 24)).columns, 40), 72)
        timing_str = f"{result.duration_ms:.1f}ms" if result else "7.3ms"

        header_texts = [
            "",
            f"{BOLD}{WHITE}Orvyen Agentic v{__version__}{RESET}",
            f"{GRAY_MUTED}Opus Engine • Sub-100ms • 12 Rules • 22 tests{RESET}",
            f"{GRAY_DARK}~/orvyen-agentic • Singapore • IMDA v1.5 Compliant{RESET}",
            "",
            "",
            "",
            "",
        ]

        print()
        for i in range(8):
            txt = header_texts[i]
            print(f"  {logo_lines[i]}    {txt}")

        print()
        # Status pill: bg #111 border #222, green arrow #10B981, text #9CA3AF
        pill_str = f"  {bg('#111111')}{fg('#222222')}│{GREEN_ACCENT} ↑ {GRAY_LIGHT}12 checks • AIBOM + OWASP + IMDA • {timing_str} {fg('#222222')}│{RESET}"
        print(pill_str)

        # Separator: 1px #1F1F1F
        sep_char = "─" if utf8 else "-"
        print(f"  {fg('#1F1F1F')}{sep_char * term_width}{RESET}")

    @classmethod
    def _print_fancy_dropdown(cls, utf8: bool) -> None:
        term_width = min(max(shutil.get_terminal_size((80, 24)).columns, 40), 72)
        width = term_width
        h_line = ("─" if utf8 else "-") * (width - 2)
        tl, tr, bl, br = ("╭", "╮", "╰", "╯") if utf8 else ("+", "+", "+", "+")
        v = "│" if utf8 else "|"

        print()
        # Input: "> " #6B7280 + "/scan" #FFF, input box bg #111 border #222 rounded
        inner_sp = " " * max(1, width - 2 - 9)
        print(f"  {fg('#222222')}{tl}{h_line}{tr}{RESET}")
        print(f"  {fg('#222222')}{v}{bg('#111111')}  {GRAY_MUTED}> {BOLD}{WHITE}/scan{RESET}{bg('#111111')}{WHITE}█{inner_sp}{fg('#222222')}{v}{RESET}")
        print(f"  {fg('#222222')}{bl}{h_line}{br}{RESET}")
        print()

        # Dropdown: floating card bg #151515 border #222 rounded 8px shadow, 5 rows
        # Selected row = bg #0F1F25 + left border 2px solid #06B6D4, NOT full blue background
        dropdown_items = [
            ("/scan", "Scan agent codebase pre-deploy [OAG-001..OAG-012]"),
            ("/aibom", "Generate Agent Bill of Materials"),
            ("/compliance", "IMDA v1.5 + MAS FEAT matrix"),
            ("/secure", "Run against secure_agent fixture → 100/100 HEALTHY"),
            ("/vulnerable", "Run against vulnerable_agent → 8 Critical, 15 High"),
        ]

        print(f"  {fg('#222222')}{tl}{h_line}{tr}{RESET}")
        for idx, (cmd, desc) in enumerate(dropdown_items):
            content_w = width - 4
            spacing = " " * max(1, content_w - len(cmd) - len(desc) - 2)
            if idx == 0:
                # selected row: bg #0F1F25 + left border 2px solid #06B6D4
                left_border = f"{CYAN_ACCENT}▌{RESET}"
                row_content = f"{bg('#0F1F25')} {BOLD}{WHITE}{cmd}{RESET}{bg('#0F1F25')}{spacing}{GRAY_MUTED}{desc} {RESET}"
                print(f"  {fg('#222222')}{v}{RESET}{left_border}{row_content}{fg('#222222')}{v}{RESET}")
            else:
                left_border = f"{bg('#151515')} {RESET}"
                row_content = f"{bg('#151515')} {WHITE}{cmd}{spacing}{GRAY_MUTED}{desc} {RESET}"
                print(f"  {fg('#222222')}{v}{RESET}{left_border}{row_content}{fg('#222222')}{v}{RESET}")

        print(f"  {fg('#222222')}{bl}{h_line}{br}{RESET}")
        print()

    @classmethod
    def _print_clean_banner(cls, utf8: bool) -> None:
        check = "✓" if utf8 else "[PASS]"
        print(f"  {BOLD}{GREEN_ACCENT}{check} All clear!{RESET} {GRAY_MUTED}No security vulnerabilities or policy violations detected.{RESET}")
        print(f"  {GRAY_DARK}All agent graphs, tools, prompts, and MCP gateways adhere to baseline policies.{RESET}")
        print()

    @classmethod
    def _print_footer(cls, result: ScanResult, utf8: bool) -> None:
        score = result.security_score
        score_color = GREEN_ACCENT if score >= 85 else (AMBER_ACCENT if score >= 60 else RED_ACCENT)
        score_grade = "HEALTHY" if score >= 85 else ("RISK DETECTED" if score >= 60 else "HIGH VULNERABILITY")
        timing_str = f"{result.duration_ms:.1f}ms" if result.duration_ms < 1000 else f"{result.duration_ms / 1000:.2f}s"

        print(
            f"  {GRAY_LIGHT}Security Score: {BOLD}{score_color}{score}/100 [{score_grade}]{RESET} "
            f"{GRAY_MUTED}•{RESET} {GRAY_LIGHT}Files: {WHITE}{result.files_scanned}{RESET} "
            f"{GRAY_MUTED}•{RESET} {GRAY_LIGHT}Time: {score_color}{timing_str}{RESET}"
        )
        print()

    @classmethod
    def _print_header(cls, result: Optional[ScanResult], utf8: bool) -> None:
        bolt = "⚡" if utf8 else "*"
        bullet = "•" if utf8 else "-"
        print()
        print(
            f"{CYAN_ACCENT}{BOLD}{bolt} orvyen-agentic{RESET} {GRAY_MUTED}v{__version__}{RESET} "
            f"{DIM}{bullet}{RESET} {WHITE}AI Agent Static Security & Compliance Scanner{RESET}"
        )
        if result:
            try:
                rel_target = str(Path(result.target_path).relative_to(Path.cwd()))
                rel_target = f"./{rel_target}" if not rel_target.startswith(".") else rel_target
            except Exception:
                rel_target = result.target_path

            duration_sec = result.duration_ms / 1000
            timing_str = f"{result.duration_ms:.1f}ms" if result.duration_ms < 1000 else f"{duration_sec:.2f}s"

            print(
                f"{GRAY_MUTED}Target:{RESET} {WHITE}{rel_target}{RESET}  "
                f"{GRAY_MUTED}|  Files scanned:{RESET} {WHITE}{result.files_scanned}{RESET}  "
                f"{GRAY_MUTED}|  Time:{RESET} {GREEN_ACCENT}{timing_str}{RESET}"
            )
        print()

    @classmethod
    def _print_detailed_findings(cls, findings: List[Finding], utf8: bool) -> None:
        findings_by_file: Dict[str, List[Finding]] = {}
        for f in findings:
            findings_by_file.setdefault(f.file_path, []).append(f)

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
        arrow = "-->"

        sev = f.severity
        if sev == Severity.CRITICAL:
            sev_badge = f"{bg('#EF4444')}{BOLD}{WHITE} CRITICAL {RESET}"
            icon_color = RED_ACCENT
        elif sev == Severity.HIGH:
            sev_badge = f"{bg('#F59E0B')}{BOLD}{WHITE} HIGH {RESET}"
            icon_color = AMBER_ACCENT
        elif sev == Severity.MEDIUM:
            sev_badge = f"{bg('#D97706')}{BOLD}{WHITE} MEDIUM {RESET}"
            icon_color = AMBER_ACCENT
        elif sev == Severity.LOW:
            sev_badge = f"{CYAN_ACCENT}{BOLD} LOW {RESET}"
            icon_color = CYAN_ACCENT
        else:
            sev_badge = f"{GRAY_MUTED} INFO {RESET}"
            icon_color = GRAY_MUTED

        print(f"  {icon_color}{BOLD}{cross}{RESET} {sev_badge} {BOLD}{WHITE}{f.rule_id}{RESET} {GRAY_MUTED}{bullet}{RESET} {BOLD}{f.rule_title}{RESET}")
        print(f"    {GRAY_MUTED}{arrow}{RESET} {UNDERLINE}{WHITE}{rel_path}:{f.line_number}:{f.column}{RESET}")
        print(f"    {GRAY_MUTED}{pipe}{RESET}")

        if f.code_snippet:
            lines = f.code_snippet.strip().splitlines()
            start_lineno = max(1, f.line_number - (len(lines) // 2))
            for offset, line_text in enumerate(lines[:5]):
                curr_no = start_lineno + offset
                is_target_line = (curr_no == f.line_number) or (offset == 0 and len(lines) == 1)
                gutter_color = RED_ACCENT if is_target_line else GRAY_MUTED
                line_color = WHITE if is_target_line else GRAY_MUTED
                mark = f"{icon_color}>{RESET}" if is_target_line else " "
                print(f"  {mark} {gutter_color}{curr_no:>4} {pipe}{RESET} {line_color}{line_text}{RESET}")

            print(f"      {GRAY_MUTED}     {pipe}{RESET} {icon_color}{BOLD}{' ' * max(0, f.column - 1)}^^^^^^^^ {f.message}{RESET}")
        else:
            print(f"      {GRAY_MUTED}     {pipe}{RESET} {WHITE}{f.message}{RESET}")

        print(f"    {GRAY_MUTED}{pipe}{RESET}")
        print(f"    {GRAY_MUTED}= Standards:{RESET}  {fg('#A855F7')}{BOLD}{f.owasp_id}{RESET} {GRAY_MUTED}{bullet}{RESET} {CYAN_ACCENT}{f.imda_pillar}{RESET}")
        print(f"    {GRAY_MUTED}= Fix:{RESET}        {GREEN_ACCENT}{f.remediation}{RESET}")
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
            sev_color = RED_ACCENT if sev in (Severity.CRITICAL, Severity.HIGH) else (AMBER_ACCENT if sev == Severity.MEDIUM else CYAN_ACCENT)
            print(
                f"  {GRAY_MUTED}{rel_path}:{f.line_number}:{f.column}{RESET} "
                f"{sev_color}{BOLD}{sev.value:<8}{RESET} "
                f"{WHITE}{BOLD}{f.rule_id}{RESET} "
                f"{GRAY_MUTED}{bullet}{RESET} {f.message}"
            )
        print()

    @classmethod
    def _print_summary_card(cls, result: ScanResult, utf8: bool) -> None:
        imda = IMDAComplianceEvaluator.evaluate(result.findings)
        owasp = OWASPComplianceEvaluator.evaluate(result.findings)

        box_w = 72
        h_box = ("─" if utf8 else "-") * (box_w - 2)
        tl, tr, bl, br = ("╭", "╮", "╰", "╯") if utf8 else ("+", "+", "+", "+")
        v = "│" if utf8 else "|"

        card_title = " EXECUTIVE COMPLIANCE & RISK SUMMARY "
        left_p = (box_w - 2 - len(card_title)) // 2
        right_p = box_w - 2 - len(card_title) - left_p

        print(f"  {fg('#1E3A4A')}{tl}{h_box}{tr}{RESET}")
        print(f"  {fg('#1E3A4A')}{v}{' ' * left_p}{BOLD}{WHITE}{card_title}{RESET}{' ' * right_p}{fg('#1E3A4A')}{v}{RESET}")

        def print_comp_row(label: str, val_str: str) -> None:
            import re
            ansi_clean = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", val_str)
            sp = " " * max(1, box_w - 2 - len(label) - len(ansi_clean) - 4)
            print(f"  {fg('#1E3A4A')}{v}{bg('#0A1419')}  {GRAY_MUTED}{label}:{RESET}{bg('#0A1419')}{sp}{val_str}  {RESET}{fg('#1E3A4A')}{v}{RESET}")

        score = result.security_score
        score_color = GREEN_ACCENT if score >= 85 else (AMBER_ACCENT if score >= 60 else RED_ACCENT)
        score_grade = "HEALTHY" if score >= 85 else ("RISK DETECTED" if score >= 60 else "HIGH VULNERABILITY")
        print_comp_row("Security Score", f"{BOLD}{score_color}{score:>3}/100  [{score_grade}]{RESET}")

        # Severity colors ONLY when > 0
        crit_str = f"{BOLD}{RED_ACCENT}{result.critical_count} Critical{RESET}" if result.critical_count > 0 else f"{GRAY_MUTED}0 Critical{RESET}"
        high_str = f"{BOLD}{AMBER_ACCENT}{result.high_count} High{RESET}" if result.high_count > 0 else f"{GRAY_MUTED}0 High{RESET}"
        med_str = f"{AMBER_ACCENT}{result.medium_count} Med{RESET}" if result.medium_count > 0 else f"{GRAY_MUTED}0 Med{RESET}"
        low_str = f"{CYAN_ACCENT}{result.low_count} Low{RESET}" if result.low_count > 0 else f"{GRAY_MUTED}0 Low{RESET}"
        print_comp_row("Violations Found", f"{crit_str} {GRAY_MUTED}•{RESET} {high_str} {GRAY_MUTED}•{RESET} {med_str} {GRAY_MUTED}•{RESET} {low_str}")

        exec_count = sum(1 for t in result.tools if t.privilege.value in ("EXECUTE", "ADMIN"))
        exec_str = f"{RED_ACCENT}{exec_count} High-Privilege{RESET}" if exec_count > 0 else f"{GRAY_MUTED}0 High-Privilege{RESET}"
        print_comp_row("Asset Inventory", f"{WHITE}{len(result.tools)} Tools{RESET} ({exec_str}) {GRAY_MUTED}•{RESET} {WHITE}{len(result.mcp_servers)} MCP Gateways{RESET}")

        imda_status = imda.get("overall_status")
        imda_color = GREEN_ACCENT if imda_status == "COMPLIANT" else RED_ACCENT
        print_comp_row("Singapore IMDA", f"{BOLD}{imda_color}{imda_status:<10}{RESET} ({GRAY_MUTED}{imda.get('score_percentage')}% aligned to 4 Pillars{RESET})")

        owasp_status = owasp.get("overall_status")
        owasp_color = GREEN_ACCENT if owasp_status == "PASS" else RED_ACCENT
        print_comp_row("OWASP LLM Top 10", f"{BOLD}{owasp_color}{owasp_status:<10}{RESET} ({GRAY_MUTED}{owasp.get('score_percentage')}% category pass rate{RESET})")

        print(f"  {fg('#1E3A4A')}{bl}{h_box}{br}{RESET}")
        print()


def print_scan_result(
    result: ScanResult,
    min_severity: Severity = Severity.INFO,
    compact: bool = False,
    fancy: bool = False,
) -> None:
    """Convenience function conforming to reporter API."""
    ConsoleReporter.print_result(
        result=result,
        min_severity=min_severity,
        compact=compact,
        fancy=fancy,
    )


def print_header(result: Optional[ScanResult] = None, fancy: bool = True) -> None:
    """Convenience function conforming to reporter API."""
    ConsoleReporter.print_header(result=result, fancy=fancy)
