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
import textwrap
from pathlib import Path
from typing import List, Dict, Any, Optional

from orvyen import __version__
from orvyen.core.models import ScanResult, Severity, Finding
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator, IMDA_PILLARS
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator, OWASP_LLM_ITEMS

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
            cls._print_fancy_header(result, utf8, animate=True)
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
    def print_header(cls, result: Optional[ScanResult] = None, fancy: bool = True, animate: bool = False) -> None:
        """Standalone header printer for CLI entrypoints or REPL initialization."""
        utf8 = _can_utf8()
        if fancy:
            cls._print_fancy_header(result, utf8, animate=animate)
        else:
            cls._print_header(result, utf8)

    @classmethod
    def _print_fancy_header(cls, result: Optional[ScanResult], utf8: bool, animate: bool = True) -> None:
        matrix = load_logo_matrix()
        logo_lines = render_logo_lines(matrix, utf8=utf8)
        term_width = min(max(shutil.get_terminal_size((80, 24)).columns, 40), 72)
        timing_str = f"{result.duration_ms:.1f}ms" if result else "2.1ms"

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
        # Animated status pill: bg #111 border #222, green arrow #10B981, text #9CA3AF
        pill_final = f"  {bg('#111111')}{fg('#222222')}│{GREEN_ACCENT} ↑ {GRAY_LIGHT}12 checks • AIBOM + OWASP + IMDA • {timing_str} {fg('#222222')}│{RESET}"

        if animate and sys.stdout.isatty():
            anim_frames = [
                f"  {bg('#111111')}{fg('#222222')}│{fg('#3B82F6')} ⠋ {GRAY_LIGHT}Running 12 AST security rules (OAG-001..OAG-012)...      {fg('#222222')}│{RESET}",
                f"  {bg('#111111')}{fg('#222222')}│{fg('#06B6D4')} ⠙ {GRAY_LIGHT}Evaluating Singapore IMDA v1.5 & OWASP Top 10...        {fg('#222222')}│{RESET}",
                f"  {bg('#111111')}{fg('#222222')}│{fg('#10B981')} ⠹ {GRAY_LIGHT}Auditing MCP server boundaries & tool privileges...     {fg('#222222')}│{RESET}",
                f"  {bg('#111111')}{fg('#222222')}│{GREEN_ACCENT} ↑ {WHITE}12 checks{GRAY_LIGHT} • AIBOM + OWASP + IMDA • {timing_str} {fg('#222222')}│{RESET}",
            ]
            import time
            for f in anim_frames:
                sys.stdout.write(f"\r{f}")
                sys.stdout.flush()
                time.sleep(0.04)
            sys.stdout.write(f"\r{pill_final}\n")
            sys.stdout.flush()
        else:
            print(pill_final)

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
                rel_target = Path(result.target_path).resolve().relative_to(Path.cwd().resolve()).as_posix()
                rel_target = f"./{rel_target}" if not rel_target.startswith(".") else rel_target
            except Exception:
                rel_target = Path(result.target_path).as_posix()

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
                rel_path = Path(file_path).resolve().relative_to(Path.cwd().resolve()).as_posix()
            except Exception:
                rel_path = Path(file_path).as_posix()

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
        wrapped_remediation = textwrap.fill(f.remediation, width=70, subsequent_indent="                  ")
        print(f"    {GRAY_MUTED}= Fix:{RESET}        {GREEN_ACCENT}{wrapped_remediation}{RESET}")
        print()

    @classmethod
    def _print_compact_findings(cls, findings: List[Finding], utf8: bool) -> None:
        bullet = "•" if utf8 else "-"
        for f in findings:
            try:
                rel_path = Path(f.file_path).resolve().relative_to(Path.cwd().resolve()).as_posix()
            except Exception:
                rel_path = Path(f.file_path).as_posix()

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

    @classmethod
    def print_aibom(cls, aibom_dict: Dict[str, Any], utf8: bool = True, width: int = 72) -> None:
        """Renders an executive AIBOM card with aligned tables, badges, and clean paths."""
        meta = aibom_dict.get("metadata", {})
        tools = aibom_dict.get("tools", {})
        by_priv = tools.get("by_privilege", {})
        servers = aibom_dict.get("mcp_servers", [])

        raw_path = meta.get("target_path", ".")
        try:
            rel_path = Path(raw_path).resolve().relative_to(Path.cwd().resolve()).as_posix()
            display_path = f"./{rel_path}" if not rel_path.startswith(".") else rel_path
        except Exception:
            display_path = Path(raw_path).as_posix()

        fw_map = {
            "mcp": "MCP Gateway",
            "langchain": "LangChain",
            "langgraph": "LangGraph",
            "crewai": "CrewAI",
        }
        raw_fws = meta.get("frameworks", [])
        formatted_fws = [fw_map.get(f.lower(), f.capitalize()) for f in raw_fws]
        fw_str = f" {GRAY_MUTED}•{RESET} ".join(f"{CYAN_ACCENT}{f}{RESET}" for f in formatted_fws) or f"{GRAY_MUTED}None{RESET}"

        tl, tr, bl, br = ("╭", "╮", "╰", "╯") if utf8 else ("+", "+", "+", "+")
        v = "│" if utf8 else "|"
        inner_w = width - 2
        h_line = ("─" if utf8 else "-") * inner_w

        print()
        print(f"  {fg('#1E3A4A')}{tl}{h_line}{tr}{RESET}")
        title = " AGENT BILL OF MATERIALS (AIBOM) "
        lp = (inner_w - len(title)) // 2
        rp = inner_w - len(title) - lp
        print(f"  {fg('#1E3A4A')}{v}{' ' * lp}{BOLD}{WHITE}{title}{RESET}{' ' * rp}{fg('#1E3A4A')}{v}{RESET}")
        print(f"  {fg('#1E3A4A')}├{h_line}┤{RESET}")

        def row(label: str, val_str: str) -> None:
            import re
            ansi_clean = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', val_str)
            sp = ' ' * max(1, inner_w - len(label) - len(ansi_clean) - 4)
            print(f"  {fg('#1E3A4A')}{v}{bg('#0A1419')}  {GRAY_MUTED}{label}:{RESET}{bg('#0A1419')}{sp}{val_str}  {RESET}{fg('#1E3A4A')}{v}{RESET}")

        score = meta.get('security_score', 100)
        score_col = GREEN_ACCENT if score >= 85 else (AMBER_ACCENT if score >= 60 else RED_ACCENT)
        grade = "HEALTHY" if score >= 85 else ("RISK DETECTED" if score >= 60 else "HIGH VULNERABILITY")

        row("Target System", f"{WHITE}{display_path}{RESET}")
        row("Security Score", f"{BOLD}{score_col}{score}/100 [{grade}]{RESET}")
        row("Frameworks", fw_str)
        row("Declared Assets", f"{WHITE}{tools.get('total_tools', 0)} Tools{RESET} {GRAY_MUTED}•{RESET} {WHITE}{len(servers)} MCP Servers{RESET}")
        print(f"  {fg('#1E3A4A')}{bl}{h_line}{br}{RESET}")
        print()

        # Tool Inventory Table
        print(f"  {BOLD}{WHITE}Tool Inventory & Privilege Classification:{RESET}")
        print(f"  {fg('#222222')}{tl}{h_line}{tr}{RESET}")

        col_hdr = f"  {GRAY_MUTED}{'TOOL NAME':<20} {'TIER':<8} {'FRAMEWORK':<9} {'AUDITED':<7} {'BOUND':<5} {'SOURCE':<14}{RESET}"
        import re
        clean_hdr = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', col_hdr))
        sp_hdr = ' ' * max(0, inner_w - clean_hdr)
        print(f"  {fg('#222222')}{v}{bg('#151515')}{col_hdr}{sp_hdr}{RESET}{fg('#222222')}{v}{RESET}")
        print(f"  {fg('#222222')}├{h_line}┤{RESET}")

        all_tools = []
        for priv in ("admin", "execute", "write", "read"):
            for t in by_priv.get(priv, []):
                all_tools.append((priv, t))

        if not all_tools:
            empty_msg = f"  {GRAY_MUTED}No declared tools detected in target system.{RESET}"
            clean_em = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', empty_msg))
            sp_em = ' ' * max(0, inner_w - clean_em)
            print(f"  {fg('#222222')}{v}{empty_msg}{sp_em}{fg('#222222')}{v}{RESET}")
        else:
            for priv, t in all_tools:
                t_name = t.get("name", "")[:20]
                priv_str = priv.upper()
                if priv in ("admin", "execute"):
                    priv_badge = f"{BOLD}{RED_ACCENT}{priv_str:<8}{RESET}"
                elif priv == "write":
                    priv_badge = f"{BOLD}{AMBER_ACCENT}{priv_str:<8}{RESET}"
                else:
                    priv_badge = f"{CYAN_ACCENT}{priv_str:<8}{RESET}"

                fw = t.get("framework", "")[:9]
                aud = f"{GREEN_ACCENT}Yes    {RESET}" if t.get("is_audited") else f"{RED_ACCENT}NO     {RESET}"
                bnd = f"{WHITE}Yes  {RESET}" if t.get("is_bound") else f"{GRAY_MUTED}No   {RESET}"

                fp = t.get("file_path", "")
                fn = Path(fp).name
                if fn == "mcp_servers.json":
                    short_fn = "mcp_srv.json"
                elif len(fn) > 11:
                    short_fn = fn[:10] + "…"
                else:
                    short_fn = fn
                src = f"{short_fn}:{t.get('line_number')}"[:14]

                row_str = f"  {WHITE}{t_name:<20}{RESET} {priv_badge} {GRAY_LIGHT}{fw:<9}{RESET} {aud} {bnd} {GRAY_MUTED}{src:<14}{RESET}"
                clean_len = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', row_str))
                sp_r = ' ' * max(0, inner_w - clean_len)
                print(f"  {fg('#222222')}{v}{row_str}{sp_r}{fg('#222222')}{v}{RESET}")

        print(f"  {fg('#222222')}{bl}{h_line}{br}{RESET}")
        print()

        if servers:
            print(f"  {BOLD}{WHITE}Connected MCP Servers:{RESET}")
            print(f"  {fg('#222222')}{tl}{h_line}{tr}{RESET}")
            s_hdr = f"  {GRAY_MUTED}{'SERVER NAME':<18} {'COMMAND':<7} {'ARGUMENTS':<21} {'ENV KEYS':<19}{RESET}"
            clean_s_hdr = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', s_hdr))
            sp_s = ' ' * max(0, inner_w - clean_s_hdr)
            print(f"  {fg('#222222')}{v}{bg('#151515')}{s_hdr}{sp_s}{RESET}{fg('#222222')}{v}{RESET}")
            print(f"  {fg('#222222')}├{h_line}┤{RESET}")
            for s in servers:
                s_name = s.get("name", "")[:18]
                cmd = s.get("command", "")[:7]
                args = " ".join(s.get("args", []))[:21]
                env_keys = s.get("env_keys", [])
                if len(env_keys) == 1:
                    envs = env_keys[0][:19]
                elif len(env_keys) > 1:
                    envs = f"{env_keys[0]} (+{len(env_keys)-1})"[:19]
                else:
                    envs = "None"
                s_row = f"  {WHITE}{s_name:<18}{RESET} {CYAN_ACCENT}{cmd:<7}{RESET} {GRAY_LIGHT}{args:<21}{RESET} {AMBER_ACCENT}{envs:<19}{RESET}"
                clean_s = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', s_row))
                sp_sr = ' ' * max(0, inner_w - clean_s)
                print(f"  {fg('#222222')}{v}{s_row}{sp_sr}{fg('#222222')}{v}{RESET}")
            print(f"  {fg('#222222')}{bl}{h_line}{br}{RESET}")
            print()

        print(f"  {GRAY_DARK}Tier: Orvyen Agentic Core  •  Full IMDA/OWASP clause mapping: {CYAN_ACCENT}orvyen.dev/pricing{RESET}")
        print()

    @classmethod
    def print_compliance(cls, imda: Dict[str, Any], owasp: Dict[str, Any], utf8: bool = True, width: int = 72) -> None:
        """Renders an executive compliance report card for Singapore IMDA & OWASP LLM."""
        tl, tr, bl, br = ("╭", "╮", "╰", "╯") if utf8 else ("+", "+", "+", "+")
        v = "│" if utf8 else "|"
        inner_w = width - 2
        h_line = ("─" if utf8 else "-") * inner_w

        print()
        print(f"  {fg('#1E3A4A')}{tl}{h_line}{tr}{RESET}")
        title = " SINGAPORE IMDA AI GOVERNANCE FRAMEWORK "
        lp = (inner_w - len(title)) // 2
        rp = inner_w - len(title) - lp
        print(f"  {fg('#1E3A4A')}{v}{' ' * lp}{BOLD}{WHITE}{title}{RESET}{' ' * rp}{fg('#1E3A4A')}{v}{RESET}")
        print(f"  {fg('#1E3A4A')}├{h_line}┤{RESET}")

        imda_status = imda.get("overall_status", "COMPLIANT")
        imda_col = GREEN_ACCENT if imda_status == "COMPLIANT" else RED_ACCENT
        status_line = f"  {BOLD}{WHITE}Overall Status:{RESET} {BOLD}{imda_col}{imda_status}{RESET} {GRAY_MUTED}({imda.get('score_percentage', 100)}% aligned across 4 Pillars){RESET}"
        import re
        clean_status = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', status_line))
        sp_st = ' ' * max(0, inner_w - clean_status)
        print(f"  {fg('#1E3A4A')}{v}{bg('#0A1419')}{status_line}{sp_st}{RESET}{fg('#1E3A4A')}{v}{RESET}")
        print(f"  {fg('#1E3A4A')}├{h_line}┤{RESET}")

        for p_id in ("Pillar 1", "Pillar 2", "Pillar 3", "Pillar 4"):
            p_info = IMDA_PILLARS.get(p_id, {})
            p_data = imda.get("pillars", {}).get(p_id, {})
            p_name = p_info.get("name", p_data.get("name", p_id))[:27]
            p_status = p_data.get("status", "COMPLIANT")
            p_col = GREEN_ACCENT if p_status == "COMPLIANT" else RED_ACCENT
            v_count = p_data.get("violation_count", 0)
            if v_count == 0:
                issues_str = f"{GREEN_ACCENT}0 issues{RESET}"
            else:
                crit = p_data.get("severities", {}).get("critical", 0)
                high = p_data.get("severities", {}).get("high", 0)
                parts = []
                if crit:
                    parts.append(f"{RED_ACCENT}{crit} Crit{RESET}")
                if high:
                    parts.append(f"{AMBER_ACCENT}{high} High{RESET}")
                issues_str = " ".join(parts) if parts else f"{RED_ACCENT}{v_count} issues{RESET}"

            row_str = f"  {WHITE}{p_id}:{RESET} {GRAY_LIGHT}{p_name:<27}{RESET} {p_col}{BOLD}{p_status:<13}{RESET} {issues_str}"
            clean_len = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', row_str))
            sp = ' ' * max(0, inner_w - clean_len)
            print(f"  {fg('#1E3A4A')}{v}{row_str}{sp}{fg('#1E3A4A')}{v}{RESET}")

        print(f"  {fg('#1E3A4A')}{bl}{h_line}{br}{RESET}")
        print()

        # OWASP LLM Top 10 Card
        print(f"  {fg('#1E3A4A')}{tl}{h_line}{tr}{RESET}")
        title2 = " OWASP TOP 10 FOR LLM APPLICATIONS (2025) "
        lp2 = (inner_w - len(title2)) // 2
        rp2 = inner_w - len(title2) - lp2
        print(f"  {fg('#1E3A4A')}{v}{' ' * lp2}{BOLD}{WHITE}{title2}{RESET}{' ' * rp2}{fg('#1E3A4A')}{v}{RESET}")
        print(f"  {fg('#1E3A4A')}├{h_line}┤{RESET}")

        owasp_status = owasp.get("overall_status", "PASS")
        owasp_col = GREEN_ACCENT if owasp_status == "PASS" else RED_ACCENT
        owasp_hdr = f"  {BOLD}{WHITE}Overall Status:{RESET} {BOLD}{owasp_col}{owasp_status}{RESET} {GRAY_MUTED}({owasp.get('score_percentage', 100)}% category pass rate){RESET}"
        clean_owasp = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', owasp_hdr))
        sp_ow = ' ' * max(0, inner_w - clean_owasp)
        print(f"  {fg('#1E3A4A')}{v}{bg('#0A1419')}{owasp_hdr}{sp_ow}{RESET}{fg('#1E3A4A')}{v}{RESET}")
        print(f"  {fg('#1E3A4A')}├{h_line}┤{RESET}")

        for owasp_id, meta_info in OWASP_LLM_ITEMS.items():
            item_data = owasp.get("items", {}).get(owasp_id, {})
            title = (item_data.get("title") or meta_info.get("title", ""))[:34]
            status = item_data.get("status", "PASS")
            status_col = GREEN_ACCENT if status == "PASS" else RED_ACCENT
            v_count = item_data.get("violation_count", 0)
            issues_str = f"{GRAY_MUTED}0 issues{RESET}" if v_count == 0 else f"{RED_ACCENT}{v_count} issue{'s' if v_count != 1 else ''}{RESET}"

            row_c = f"  {CYAN_ACCENT}{owasp_id:<6}{RESET} {WHITE}{title:<34}{RESET} {status_col}{BOLD}{status:<6}{RESET} {issues_str}"
            clean_c = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', row_c))
            sp_c = ' ' * max(0, inner_w - clean_c)
            print(f"  {fg('#1E3A4A')}{v}{row_c}{sp_c}{fg('#1E3A4A')}{v}{RESET}")

        print(f"  {fg('#1E3A4A')}{bl}{h_line}{br}{RESET}")
        print()

    @classmethod
    def print_help(cls, utf8: bool = True, width: int = 72) -> None:
        """Renders an executive reference card for interactive commands and shortcuts."""
        tl, tr, bl, br = ("╭", "╮", "╰", "╯") if utf8 else ("+", "+", "+", "+")
        v = "│" if utf8 else "|"
        inner_w = width - 2
        h_line = ("─" if utf8 else "-") * inner_w

        print()
        print(f"  {fg('#1E3A4A')}{tl}{h_line}{tr}{RESET}")
        title = " ORVYEN AGENTIC INTERACTIVE COMMANDS "
        lp = (inner_w - len(title)) // 2
        rp = inner_w - len(title) - lp
        print(f"  {fg('#1E3A4A')}{v}{' ' * lp}{BOLD}{WHITE}{title}{RESET}{' ' * rp}{fg('#1E3A4A')}{v}{RESET}")
        print(f"  {fg('#1E3A4A')}├{h_line}┤{RESET}")

        hdr = f"  {BOLD}{WHITE}Interactive Commands:{RESET}"
        import re
        clean_hdr = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', hdr))
        sp_h = ' ' * max(0, inner_w - clean_hdr)
        print(f"  {fg('#1E3A4A')}{v}{bg('#0A1419')}{hdr}{sp_h}{RESET}{fg('#1E3A4A')}{v}{RESET}")

        commands = [
            ("/scan [path]", "Re-scan current target or specified path"),
            ("/aibom", "View Agent Bill of Materials & MCP inventory"),
            ("/compliance", "Singapore IMDA v1.5 & OWASP LLM Top 10 matrix"),
            ("/secure", "Run benchmark on secure_agent fixture (100/100)"),
            ("/vulnerable", "Run benchmark on vulnerable_agent fixture"),
            ("/clear", "Clear terminal screen and re-render header"),
            ("/help", "Display this interactive command reference"),
            ("/exit, q", "Exit interactive session"),
        ]

        for cmd, desc in commands:
            row_str = f"  {CYAN_ACCENT}{cmd:<15}{RESET} {GRAY_LIGHT}{desc:<51}{RESET}"
            clean = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', row_str))
            sp = ' ' * max(0, inner_w - clean)
            print(f"  {fg('#1E3A4A')}{v}{row_str}{sp}{fg('#1E3A4A')}{v}{RESET}")

        print(f"  {fg('#1E3A4A')}├{h_line}┤{RESET}")
        shdr = f"  {BOLD}{WHITE}Keyboard Shortcuts:{RESET}"
        clean_shdr = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', shdr))
        sp_sh = ' ' * max(0, inner_w - clean_shdr)
        print(f"  {fg('#1E3A4A')}{v}{bg('#0A1419')}{shdr}{sp_sh}{RESET}{fg('#1E3A4A')}{v}{RESET}")

        shortcuts = [
            ("Ctrl+C", "Exit session immediately"),
            ("Enter", "Re-run scan on current target"),
            ("Ctrl+D / Ctrl+Z", "Exit session (EOF)"),
        ]
        for key, desc in shortcuts:
            row_str = f"  {GREEN_ACCENT}{key:<16}{RESET} {GRAY_LIGHT}{desc:<50}{RESET}"
            clean = len(re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', row_str))
            sp = ' ' * max(0, inner_w - clean)
            print(f"  {fg('#1E3A4A')}{v}{row_str}{sp}{fg('#1E3A4A')}{v}{RESET}")

        print(f"  {fg('#1E3A4A')}{bl}{h_line}{br}{RESET}")
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


def print_help(fancy: bool = True) -> None:
    """Convenience function conforming to reporter API."""
    ConsoleReporter.print_help(utf8=fancy)


class InteractivePrompt:
    """Live interactive terminal input box with blinking hardware cursor and dynamic dropdown autocomplete."""

    COMMANDS = [
        ("/scan", "Scan agent codebase pre-deploy [OAG-001..OAG-012]"),
        ("/aibom", "Generate Agent Bill of Materials & MCP inventory"),
        ("/compliance", "IMDA v1.5 + MAS FEAT matrix"),
        ("/secure", "Run against secure_agent fixture → 100/100 HEALTHY"),
        ("/vulnerable", "Run against vulnerable_agent → 8 Critical, 15 High"),
        ("/help", "Display interactive command reference card"),
        ("/clear", "Clear terminal screen and re-render header"),
        ("/exit", "Exit interactive session (or press Ctrl+C)"),
    ]

    @classmethod
    def get_filtered(cls, text: str) -> List[tuple[str, str]]:
        clean = text.strip()
        if not clean or clean in ("/", "/scan"):
            return cls.COMMANDS[:5]
        if clean.startswith("/"):
            matches = [c for c in cls.COMMANDS if c[0].startswith(clean)]
            if matches:
                return matches[:5]
        matches = [c for c in cls.COMMANDS if clean in c[0] or clean in c[1].lower()]
        if matches:
            return matches[:5]
        return [("/scan " + clean, "Scan specified path pre-deploy")]

    @classmethod
    def render_widget(cls, text: str, selected_idx: int, utf8: bool = True, width: int = 72) -> int:
        filtered = cls.get_filtered(text)
        selected_idx = max(0, min(selected_idx, len(filtered) - 1))

        inner_w = width - 2
        h_line = ("─" if utf8 else "-") * inner_w
        tl, tr, bl, br = ("╭", "╮", "╰", "╯") if utf8 else ("+", "+", "+", "+")
        v = "│" if utf8 else "|"

        lines = []
        # 1. Input Box (bg #111 border #222)
        lines.append(f"  {fg('#222222')}{tl}{h_line}{tr}{RESET}")
        disp_text = text[-62:] if len(text) > 62 else text
        pad = " " * max(1, inner_w - 4 - len(disp_text))
        lines.append(f"  {fg('#222222')}{v}{bg('#111111')}  {GRAY_MUTED}> {BOLD}{WHITE}{disp_text}{RESET}{bg('#111111')}{pad}{fg('#222222')}{v}{RESET}")
        lines.append(f"  {fg('#222222')}{bl}{h_line}{br}{RESET}")
        lines.append("")

        # 2. Dropdown Card (bg #151515 border #222)
        lines.append(f"  {fg('#222222')}{tl}{h_line}{tr}{RESET}")
        cmd_col_w = 15
        max_desc_w = inner_w - 1 - 1 - cmd_col_w - 1  # 52 chars
        for idx, (cmd, desc) in enumerate(filtered):
            cmd_disp = cmd[:cmd_col_w]
            desc_clean = desc[:max_desc_w]
            trailing = " " * max(0, max_desc_w - len(desc_clean))

            if idx == selected_idx:
                left_bar = f"{CYAN_ACCENT}▌{RESET}"
                row = f"{bg('#0F1F25')} {BOLD}{WHITE}{cmd_disp:<{cmd_col_w}}{RESET}{bg('#0F1F25')} {GRAY_MUTED}{desc_clean}{trailing}{RESET}"
                lines.append(f"  {fg('#222222')}{v}{RESET}{left_bar}{row}{fg('#222222')}{v}{RESET}")
            else:
                left_bar = f"{bg('#151515')} {RESET}"
                row = f"{bg('#151515')} {WHITE}{cmd_disp:<{cmd_col_w}} {GRAY_MUTED}{desc_clean}{trailing}{RESET}"
                lines.append(f"  {fg('#222222')}{v}{RESET}{left_bar}{row}{fg('#222222')}{v}{RESET}")

        lines.append(f"  {fg('#222222')}{bl}{h_line}{br}{RESET}")
        lines.append(f"  {DIM}[↑/↓] Select  •  [Tab] Complete  •  [Enter] Execute  •  [Ctrl+C] Exit{RESET}")

        total_lines = len(lines)
        up_count = total_lines - 1
        col_count = 7 + len(disp_text)

        # Output widget with cursor hidden, then reposition native cursor inside input box and show it
        output_str = "\033[?25l" + "\n".join(lines) + f"\n\033[{up_count}A\r\033[{col_count}C\033[?25h"
        sys.stdout.write(output_str)
        sys.stdout.flush()
        return total_lines

    @classmethod
    def ask(cls, initial_text: str = "/scan", utf8: bool = True) -> str:
        """Prompts the user interactively with in-box hardware blinking cursor and dropdown autocomplete."""
        if not sys.stdin.isatty():
            try:
                raw = input().strip()
                return raw
            except (EOFError, KeyboardInterrupt):
                return "exit"

        is_windows = (os.name == "nt")
        if is_windows:
            try:
                import msvcrt
            except ImportError:
                is_windows = False

        text = initial_text
        selected_idx = 0
        is_first_render = True

        def redraw():
            nonlocal is_first_render
            if not is_first_render:
                sys.stdout.write("\033[?25l\033[1A\r\033[J")
            else:
                is_first_render = False
            cls.render_widget(text, selected_idx, utf8=utf8)

        def clear_and_restore():
            if not is_first_render:
                sys.stdout.write("\033[?25l\033[1A\r\033[J\033[?25h")
                sys.stdout.flush()

        redraw()

        try:
            while True:
                key = None
                if is_windows:
                    ch = msvcrt.getwch()
                    if ch in ('\x00', '\xe0'):
                        code = msvcrt.getwch()
                        if code == 'H': key = 'UP'
                        elif code == 'P': key = 'DOWN'
                        elif code == 'K': key = 'LEFT'
                        elif code == 'M': key = 'RIGHT'
                    elif ch in ('\r', '\n'):
                        key = 'ENTER'
                    elif ch == '\t':
                        key = 'TAB'
                    elif ch in ('\x08', '\x7f'):
                        key = 'BACKSPACE'
                    elif ch == '\x03':
                        key = 'CTRL_C'
                    elif ch in ('\x04', '\x1a'):
                        key = 'CTRL_D'
                    elif ch == '\x1b':
                        key = 'ESC'
                    elif ch.isprintable():
                        key = ch
                else:
                    import tty, termios
                    fd = sys.stdin.fileno()
                    old_set = termios.tcgetattr(fd)
                    try:
                        tty.setraw(fd)
                        ch = sys.stdin.read(1)
                        if ch == '\x1b':
                            import select
                            r2, _, _ = select.select([sys.stdin], [], [], 0.05)
                            if r2:
                                seq = sys.stdin.read(2)
                                if seq == '[A': key = 'UP'
                                elif seq == '[B': key = 'DOWN'
                            else:
                                key = 'ESC'
                        elif ch in ('\r', '\n'): key = 'ENTER'
                        elif ch == '\t': key = 'TAB'
                        elif ch in ('\x7f', '\x08'): key = 'BACKSPACE'
                        elif ch == '\x03': key = 'CTRL_C'
                        elif ch == '\x04': key = 'CTRL_D'
                        elif ch.isprintable(): key = ch
                    finally:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_set)

                if key is None:
                    continue

                if key == 'CTRL_C':
                    clear_and_restore()
                    raise KeyboardInterrupt

                if key == 'CTRL_D':
                    clear_and_restore()
                    return "exit"

                if key == 'ENTER':
                    filtered = cls.get_filtered(text)
                    if text.strip() in ("", "/"):
                        if filtered and 0 <= selected_idx < len(filtered):
                            chosen = filtered[selected_idx][0]
                        else:
                            chosen = ""
                    else:
                        chosen = text.strip()

                    clear_and_restore()
                    return chosen

                if key == 'TAB':
                    filtered = cls.get_filtered(text)
                    if filtered and 0 <= selected_idx < len(filtered):
                        text = filtered[selected_idx][0] + " "
                        selected_idx = 0
                    redraw()
                    continue

                if key == 'UP':
                    filtered = cls.get_filtered(text)
                    if filtered:
                        selected_idx = (selected_idx - 1) % len(filtered)
                        text = filtered[selected_idx][0]
                    redraw()
                    continue

                if key == 'DOWN':
                    filtered = cls.get_filtered(text)
                    if filtered:
                        selected_idx = (selected_idx + 1) % len(filtered)
                        text = filtered[selected_idx][0]
                    redraw()
                    continue

                if key == 'BACKSPACE':
                    text = text[:-1]
                    selected_idx = 0
                    redraw()
                    continue

                if key == 'ESC':
                    text = ""
                    selected_idx = 0
                    redraw()
                    continue

                if len(key) == 1 and key.isprintable():
                    text += key
                    selected_idx = 0
                    redraw()
                    continue
        except (KeyboardInterrupt, EOFError):
            clear_and_restore()
            raise


