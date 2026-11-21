"""
Minimal, quiet, and polished terminal UX for Orvyen Agentic (v0.3.2).
Engineered to Claude Code / GitHub CLI standards:
- Grayscale hierarchy + single accent green (#4ade80) / red (#f87171) for errors.
- No emojis, no ASCII banners, no box borders, no gradients.
- Braille spinners resolving in-place with real timings.
- Unboxed key/value summaries with ease-out animated score counting.
- Unboxed slash command menu with keyboard navigation.
"""

from __future__ import annotations
import atexit
import os
import re
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, TypeVar

from orvyen import __version__
from orvyen.core.models import ScanResult, Severity, Finding
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator, IMDA_PILLARS
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator, OWASP_LLM_ITEMS

T = TypeVar("T")

# Ensure UTF-8 output on consoles if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Enable Virtual Terminal Processing on Windows consoles
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h_out = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
            kernel32.SetConsoleMode(h_out, mode.value | 0x0004 | 0x0001 | 0x0002)
    except Exception:
        pass


def _should_suppress_color() -> bool:
    """Check if color output should be suppressed per NO_COLOR standard or dumb terminal."""
    if "NO_COLOR" in os.environ:
        return True
    if os.environ.get("TERM") == "dumb":
        return True
    return False


_SUPPRESS_COLOR = _should_suppress_color()


def fg(hex_code: str) -> str:
    """Returns ANSI 24-bit TrueColor foreground escape sequence."""
    if _SUPPRESS_COLOR or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return ""
    hex_code = hex_code.lstrip("#")
    if len(hex_code) == 3:
        hex_code = "".join(c * 2 for c in hex_code)
    r = int(hex_code[0:2], 16)
    g = int(hex_code[2:4], 16)
    b = int(hex_code[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"


def bg(hex_code: str) -> str:
    """Background styling disabled per minimal design philosophy (never set background color)."""
    return ""


# Grayscale hierarchy + single green accent (#4ade80) and failure red (#f87171)
COLOR_PRIMARY = "#d4d4d4"
COLOR_DIM = "#7a7a7a"
COLOR_FAINT = "#4a4a4a"
COLOR_GREEN = "#4ade80"
COLOR_RED = "#f87171"
COLOR_ACCENT = "#e8e8e8"

# Text styling primitives
RESET = "" if _SUPPRESS_COLOR else "\033[0m"
BOLD = "" if _SUPPRESS_COLOR else "\033[1m"
DIM_STYLE = "" if _SUPPRESS_COLOR else "\033[2m"
ITALIC = "" if _SUPPRESS_COLOR else "\033[3m"
UNDERLINE = "" if _SUPPRESS_COLOR else "\033[4m"

# Standard minimal tokens
PRIMARY = fg(COLOR_PRIMARY)
DIM = fg(COLOR_DIM)
FAINT = fg(COLOR_FAINT)
GREEN = fg(COLOR_GREEN)
RED = fg(COLOR_RED)
ACCENT = fg(COLOR_ACCENT)

# Backward-compatible palette aliases
WHITE = PRIMARY
GRAY_LIGHT = DIM
GRAY_MUTED = DIM
GRAY_DARK = FAINT
GREEN_ACCENT = GREEN
CYAN_ACCENT = DIM
RED_ACCENT = RED
AMBER_ACCENT = DIM
LOGO_RED = RED
BORDER_COLOR = FAINT
BORDER_SUBTLE = FAINT


def force_dark_terminal() -> None:
    """No-op: respect user's native terminal background."""
    pass


def reset_terminal() -> None:
    """Ensures cursor visibility and resets terminal styling on process exit."""
    if sys.stdout.isatty():
        try:
            sys.stdout.write("\033[?25h\033[0m")
            sys.stdout.flush()
        except Exception:
            pass


atexit.register(reset_terminal)


# Braille spinner animation frames (80ms per frame)
SPIN_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def truncate_path_left(path_str: str, max_len: int = 28) -> str:
    """Truncate long file paths from the left ('.../file.py') for clean layout."""
    if len(path_str) <= max_len:
        return path_str
    return "…" + path_str[-(max_len - 1):]


def run_spinner_phase(
    label: str,
    action: Callable[[], T],
    no_anim: bool = False,
    min_visual_ms: int = 400,
) -> tuple[T, float]:
    """
    Executes a phase while showing:
    1. Running: braille spinner in faint, label in dim.
    2. Done: replaced in place with green ✓, label in dim, real elapsed time in faint.
    If fails: replaced with red ✗, error in primary on next line.
    """
    is_tty = sys.stdout.isatty() and not _should_suppress_color()
    is_ci = os.environ.get("CI") == "true"
    anim_enabled = is_tty and not no_anim and not is_ci and os.environ.get("TERM") != "dumb"

    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        cols = 80
    max_label_w = max(10, cols - 16)
    clean_label = label if len(label) <= max_label_w else label[: max_label_w - 1] + "…"

    t_start = time.perf_counter()
    err: Optional[Exception] = None
    res: Any = None

    if not anim_enabled:
        try:
            res = action()
        except Exception as e:
            err = e
        dur_ms = (time.perf_counter() - t_start) * 1000
        time_str = f"{dur_ms:.0f}ms" if dur_ms < 1000 else f"{dur_ms / 1000:.2f}s"
        if err:
            sys.stdout.write(f"{RED}✗{RESET} {DIM}{clean_label}{RESET} {FAINT}(failed){RESET}\n  {PRIMARY}{err}{RESET}\n")
            sys.stdout.flush()
            raise err
        else:
            sys.stdout.write(f"{GREEN}✓{RESET} {DIM}{clean_label}{RESET} {FAINT}({time_str}){RESET}\n")
            sys.stdout.flush()
            return res, dur_ms

    # Live animated phase running action in background thread
    action_done = threading.Event()
    action_dur_ms = 0.0

    def worker():
        nonlocal res, err, action_dur_ms
        t0 = time.perf_counter()
        try:
            res = action()
        except Exception as e:
            err = e
        finally:
            action_dur_ms = (time.perf_counter() - t0) * 1000
            action_done.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    # Hide cursor during spinner
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

    frame_idx = 0
    t_anim_start = time.perf_counter()
    min_anim_sec = min_visual_ms / 1000.0

    try:
        while True:
            frame = SPIN_FRAMES[frame_idx % len(SPIN_FRAMES)]
            sys.stdout.write(f"\r\033[K{FAINT}{frame}{RESET} {DIM}{clean_label}{RESET}")
            sys.stdout.flush()
            frame_idx += 1

            action_done.wait(timeout=0.08)
            anim_elapsed = time.perf_counter() - t_anim_start
            if action_done.is_set() and anim_elapsed >= min_anim_sec:
                break
    except KeyboardInterrupt:
        sys.stdout.write(f"\r\033[K\033[?25h\033[0m\n{DIM}cancelled{RESET}\n")
        sys.stdout.flush()
        sys.exit(130)

    # Restore cursor
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()

    real_dur_ms = action_dur_ms
    time_str = f"{real_dur_ms:.0f}ms" if real_dur_ms < 1000 else f"{real_dur_ms / 1000:.2f}s"

    target_col = min(cols - 2, 34)
    pad_len = max(2, target_col - (2 + len(clean_label) + len(time_str)))
    pad = " " * pad_len

    if err:
        sys.stdout.write(f"\r\033[K{RED}✗{RESET} {DIM}{clean_label}{RESET}\n  {PRIMARY}{err}{RESET}\n")
        sys.stdout.flush()
        raise err
    else:
        sys.stdout.write(f"\r\033[K{GREEN}✓{RESET} {DIM}{clean_label}{RESET}{pad}{FAINT}{time_str}{RESET}\n")
        sys.stdout.flush()

    return res, real_dur_ms


class ConsoleReporter:
    """Minimal, quiet, and polished terminal reporter for Orvyen Agentic."""

    _header_printed: bool = False

    @classmethod
    def print_header(
        cls,
        result: Optional[ScanResult] = None,
        target_path: Optional[str] = None,
        files_count: Optional[int] = None,
        tools_count: Optional[int] = None,
        mcp_count: Optional[int] = None,
        fancy: bool = True,
    ) -> None:
        """
        Prints minimal two-line header:
        orvyen v0.3.2 · agent security & compliance
        . · 41 files · 12 rules · 0 tools · 0 mcp
        """
        target = target_path or (result.target_path if result else ".")
        try:
            p = Path(target)
            if p.resolve() == Path.cwd().resolve():
                display_target = "."
            else:
                rel = p.resolve().relative_to(Path.cwd().resolve()).as_posix()
                display_target = f"./{rel}" if rel and not rel.startswith(".") else (rel or ".")
        except Exception:
            display_target = str(target)

        fc = files_count if files_count is not None else (result.files_scanned if result else 0)
        tc = tools_count if tools_count is not None else (len(result.tools) if result and result.tools else 0)
        mc = mcp_count if mcp_count is not None else (len(result.mcp_servers) if result and result.mcp_servers else 0)

        print(f"{BOLD}{ACCENT}orvyen{RESET} {DIM}v{__version__}{RESET} {FAINT}· agent security & compliance{RESET}")
        print(f"{FAINT}{display_target} · {fc} files · 12 rules · {tc} tools · {mc} mcp{RESET}")
        print()
        cls._header_printed = True

    @classmethod
    def print_prompt(cls, command: str = "/scan") -> None:
        """Prints prompt line: › /scan"""
        print(f"{DIM}›{RESET} {PRIMARY}{command}{RESET}\n")

    @classmethod
    def print_verdict(cls, result: ScanResult, min_severity: Severity = Severity.INFO) -> None:
        """Prints verdict line and optional unboxed findings list."""
        rule_count = 12
        total_violations = len(result.findings)
        total_time_str = f"{result.duration_ms:.0f}ms" if result.duration_ms < 1000 else f"{result.duration_ms / 1000:.2f}s"

        print()
        if total_violations == 0:
            print(f"{GREEN}✓ all clear{RESET}")
            print(f"{DIM}{rule_count} rules · 0 violations · {total_time_str}{RESET}\n")
        else:
            violation_word = "violation" if total_violations == 1 else "violations"
            print(f"{RED}✗ {total_violations} {violation_word} found{RESET}")

            parts = []
            if result.critical_count > 0:
                parts.append(f"{result.critical_count} critical")
            if result.high_count > 0:
                parts.append(f"{result.high_count} high")
            if result.medium_count > 0:
                parts.append(f"{result.medium_count} medium")
            if result.low_count > 0:
                parts.append(f"{result.low_count} low")
            sev_summary = " · ".join(parts) if parts else "0 findings"
            print(f"{DIM}{sev_summary} · {total_time_str}{RESET}\n")

            try:
                cols = shutil.get_terminal_size((80, 24)).columns
            except Exception:
                cols = 80

            # Filter findings by min_severity
            filtered_findings = [f for f in result.findings if f.severity >= min_severity]

            # Unboxed findings list
            for f in filtered_findings:
                sev_name = f.severity.value.lower()
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    sev_str = f"{RED}{sev_name:<8}{RESET}"
                elif f.severity == Severity.MEDIUM:
                    sev_str = f"{DIM}{sev_name:<8}{RESET}"
                else:
                    sev_str = f"{FAINT}{sev_name:<8}{RESET}"

                rule_id_str = f"{FAINT}{f.rule_id}{RESET}"

                try:
                    rel_p = Path(f.file_path).resolve().relative_to(Path.cwd().resolve()).as_posix()
                except Exception:
                    rel_p = Path(f.file_path).name

                rel_p_trunc = truncate_path_left(rel_p, max_len=26)
                loc_raw = f"{rel_p_trunc}:{f.line_number}"
                loc_str = f"{FAINT}{loc_raw}{RESET}"

                # Calculate remaining width for description
                fixed_w = 2 + 8 + 1 + len(f.rule_id) + 2 + len(loc_raw) + 2
                avail_desc = max(20, cols - fixed_w)

                desc = f.message
                if len(desc) > avail_desc:
                    desc = desc[: avail_desc - 1] + "…"

                print(f"  {sev_str} {rule_id_str}  {PRIMARY}{desc:<{avail_desc}}{RESET}  {loc_str}")
            print()

    @classmethod
    def print_summary(
        cls,
        result: ScanResult,
        imda: Dict[str, Any],
        owasp: Dict[str, Any],
        no_anim: bool = False,
    ) -> None:
        """Prints unboxed indented key/value summary with ease-out animated score counting."""
        target_score = result.security_score
        is_tty = sys.stdout.isatty() and not _should_suppress_color()
        anim_enabled = is_tty and not no_anim and os.environ.get("CI") != "true" and os.environ.get("TERM") != "dumb"

        key_w = 17
        k_score = f"{'score':<{key_w}}"

        if anim_enabled and target_score > 0:
            steps = 12
            duration = 0.5
            t0 = time.perf_counter()
            while True:
                elapsed = time.perf_counter() - t0
                p = min(elapsed / duration, 1.0)
                curr = round((1.0 - (1.0 - p) ** 3) * target_score)
                sys.stdout.write(f"\r\033[K  {FAINT}{k_score}{RESET}{BOLD}{PRIMARY}{curr}{RESET}{DIM}/100{RESET}")
                sys.stdout.flush()
                if p >= 1.0:
                    break
                time.sleep(duration / steps)
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            print(f"  {FAINT}{k_score}{RESET}{BOLD}{PRIMARY}{target_score}{RESET}{DIM}/100{RESET}")

        # IMDA status
        imda_status = imda.get("overall_status", "COMPLIANT")
        imda_word = "compliant" if imda_status == "COMPLIANT" else "failed"
        imda_col = GREEN if imda_status == "COMPLIANT" else RED
        imda_pillars = imda.get("pillars", {})
        comp_pillars = sum(1 for p in imda_pillars.values() if p.get("status") == "COMPLIANT")
        total_pillars = len(imda_pillars) or 4
        k_imda = f"{'imda v1.5':<{key_w}}"
        print(f"  {FAINT}{k_imda}{RESET}{imda_col}{imda_word}{RESET} {FAINT}{comp_pillars}/{total_pillars} pillars{RESET}")

        # OWASP status
        owasp_status = owasp.get("overall_status", "PASS")
        owasp_word = "pass" if owasp_status == "PASS" else "fail"
        owasp_col = GREEN if owasp_status == "PASS" else RED
        owasp_items = owasp.get("items", {})
        pass_items = sum(1 for it in owasp_items.values() if it.get("status") == "PASS")
        total_items = len(owasp_items) or 10
        k_owasp = f"{'owasp llm top 10':<{key_w}}"
        print(f"  {FAINT}{k_owasp}{RESET}{owasp_col}{owasp_word}{RESET} {FAINT}{pass_items}/{total_items}{RESET}")

        # Violations breakdown
        k_viol = f"{'violations':<{key_w}}"
        viol_str = (
            f"{result.critical_count} critical · {result.high_count} high · "
            f"{result.medium_count} medium · {result.low_count} low"
        )
        print(f"  {FAINT}{k_viol}{RESET}{DIM}{viol_str}{RESET}\n")

    @classmethod
    def print_next_step(cls, result: Optional[ScanResult] = None, command_type: str = "scan") -> None:
        """Prints contextual next-step suggestion in faint."""
        if command_type == "scan":
            if result and len(result.findings) > 0:
                print(f"{FAINT}next: {DIM}/compliance{FAINT} — inspect IMDA & OWASP regulatory requirements{RESET}\n")
            else:
                print(f"{FAINT}next: {DIM}/abom{FAINT} — generate agent bill of materials{RESET}\n")
        elif command_type in ("abom", "aibom"):
            print(f"{FAINT}next: {DIM}/compliance{FAINT} — imda & owasp matrix{RESET}\n")
        elif command_type == "compliance":
            print(f"{FAINT}next: {DIM}/scan{FAINT} — scan codebase pre-deploy{RESET}\n")
        elif command_type == "help":
            print(f"{FAINT}next: {DIM}/scan{FAINT} — scan codebase pre-deploy{RESET}\n")

    @classmethod
    def print_result(
        cls,
        result: ScanResult,
        min_severity: Severity = Severity.INFO,
        compact: bool = False,
        fancy: bool = False,
        no_anim: bool = False,
    ) -> None:
        """Renders minimal scan results conforming to specification."""
        imda = IMDAComplianceEvaluator.evaluate(result.findings)
        owasp = OWASPComplianceEvaluator.evaluate(result.findings)

        cls.print_verdict(result, min_severity=min_severity)
        cls.print_summary(result, imda, owasp, no_anim=no_anim)
        cls.print_next_step(result, command_type="scan")

    @classmethod
    def print_aibom(cls, aibom_dict: Dict[str, Any], utf8: bool = True, width: int = 72) -> None:
        """Renders minimal, unboxed Agent Bill of Materials."""
        meta = aibom_dict.get("metadata", {})
        tools = aibom_dict.get("tools", {})
        by_priv = tools.get("by_privilege", {})
        servers = aibom_dict.get("mcp_servers", [])

        raw_path = meta.get("target_path", ".")
        try:
            rel_path = Path(raw_path).resolve().relative_to(Path.cwd().resolve()).as_posix()
            display_path = f"./{rel_path}" if rel_path and not rel_path.startswith(".") else (rel_path or ".")
        except Exception:
            display_path = str(raw_path)

        fw_map = {
            "mcp": "MCP Gateway",
            "langchain": "LangChain",
            "langgraph": "LangGraph",
            "crewai": "CrewAI",
        }
        raw_fws = meta.get("frameworks", [])
        formatted_fws = [fw_map.get(f.lower(), f.capitalize()) for f in raw_fws]
        fw_str = f" {FAINT}·{RESET} ".join(f"{DIM}{f}{RESET}" for f in formatted_fws) or f"{FAINT}none{RESET}"

        score = meta.get("security_score", 100)

        key_w = 17
        print(f"  {FAINT}{'target':<{key_w}}{RESET}{DIM}{display_path}{RESET}")
        print(f"  {FAINT}{'score':<{key_w}}{RESET}{BOLD}{PRIMARY}{score}{RESET}{DIM}/100{RESET}")
        print(f"  {FAINT}{'frameworks':<{key_w}}{RESET}{fw_str}")
        print(
            f"  {FAINT}{'declared assets':<{key_w}}{RESET}"
            f"{DIM}{tools.get('total_tools', 0)} tools · {len(servers)} mcp servers{RESET}\n"
        )

        all_tools = []
        for priv in ("admin", "execute", "write", "read"):
            for t in by_priv.get(priv, []):
                all_tools.append((priv, t))

        if all_tools:
            print(f"{DIM}tools{RESET}")
            for priv, t in all_tools:
                t_name = t.get("name", "")[:24]
                priv_str = priv.lower()
                priv_col = RED if priv in ("admin", "execute") else (DIM if priv == "write" else FAINT)
                fw = t.get("framework", "")[:10]
                aud = f"{GREEN}audited{RESET}" if t.get("is_audited") else f"{FAINT}unaudited{RESET}"
                fp = t.get("file_path", "")
                fn = Path(fp).name
                src = f"{fn}:{t.get('line_number')}"[:20]

                print(f"  {priv_col}{priv_str:<8}{RESET} {PRIMARY}{t_name:<24}{RESET} {DIM}{fw:<10}{RESET} {aud:<18} {FAINT}{src}{RESET}")
            print()

        if servers:
            print(f"{DIM}mcp servers{RESET}")
            for s in servers:
                s_name = s.get("name", "")[:20]
                cmd = s.get("command", "")
                args = " ".join(s.get("args", []))[:28]
                env_keys = s.get("env_keys", [])
                envs = f"env: {env_keys[0]}" if env_keys else "no env"
                print(f"  {PRIMARY}{s_name:<20}{RESET} {DIM}{cmd} {args:<28}{RESET} {FAINT}{envs}{RESET}")
            print()

        cls.print_next_step(command_type="abom")

    @classmethod
    def print_compliance(cls, imda: Dict[str, Any], owasp: Dict[str, Any], utf8: bool = True, width: int = 72) -> None:
        """Renders minimal, unboxed compliance report for IMDA & OWASP."""
        key_w = 17
        imda_status = imda.get("overall_status", "COMPLIANT")
        imda_word = "compliant" if imda_status == "COMPLIANT" else "failed"
        imda_col = GREEN if imda_status == "COMPLIANT" else RED
        imda_pillars = imda.get("pillars", {})
        comp_pillars = sum(1 for p in imda_pillars.values() if p.get("status") == "COMPLIANT")
        total_pillars = len(imda_pillars) or 4

        owasp_status = owasp.get("overall_status", "PASS")
        owasp_word = "pass" if owasp_status == "PASS" else "fail"
        owasp_col = GREEN if owasp_status == "PASS" else RED
        owasp_items = owasp.get("items", {})
        pass_items = sum(1 for it in owasp_items.values() if it.get("status") == "PASS")
        total_items = len(owasp_items) or 10

        print(f"  {FAINT}{'imda v1.5':<{key_w}}{RESET}{imda_col}{imda_word}{RESET} {FAINT}{comp_pillars}/{total_pillars} pillars{RESET}")
        print(f"  {FAINT}{'owasp llm top 10':<{key_w}}{RESET}{owasp_col}{owasp_word}{RESET} {FAINT}{pass_items}/{total_items}{RESET}\n")

        print(f"{DIM}singapore imda{RESET}")
        for p_id in ("Pillar 1", "Pillar 2", "Pillar 3", "Pillar 4"):
            p_info = IMDA_PILLARS.get(p_id, {})
            p_data = imda.get("pillars", {}).get(p_id, {})
            p_name = p_info.get("name", p_data.get("name", p_id)).lower()
            p_status = p_data.get("status", "COMPLIANT")
            p_col = GREEN if p_status == "COMPLIANT" else RED
            p_word = "compliant" if p_status == "COMPLIANT" else "failed"
            print(f"  {FAINT}{p_id.lower():<16}{RESET} {p_col}{p_word:<10}{RESET} {DIM}{p_name}{RESET}")
        print()

        print(f"{DIM}owasp llm top 10{RESET}")
        for owasp_id, meta_info in OWASP_LLM_ITEMS.items():
            item_data = owasp.get("items", {}).get(owasp_id, {})
            title = (item_data.get("title") or meta_info.get("title", "")).lower()[:40]
            status = item_data.get("status", "PASS")
            s_col = GREEN if status == "PASS" else RED
            s_word = "pass" if status == "PASS" else "fail"
            print(f"  {FAINT}{owasp_id:<16}{RESET} {s_col}{s_word:<10}{RESET} {DIM}{title}{RESET}")
        print()

        cls.print_next_step(command_type="compliance")

    @classmethod
    def print_help(cls, utf8: bool = True, width: int = 72) -> None:
        """Renders minimal reference for commands and keyboard navigation."""
        print(f"{DIM}commands{RESET}")
        commands = [
            ("/scan [path]", "scan codebase pre-deploy"),
            ("/abom", "agent bill of materials & mcp inventory"),
            ("/compliance", "imda v1.5 & owasp llm top 10 matrix"),
            ("/secure", "benchmark secure fixture (100/100)"),
            ("/vulnerable", "benchmark vulnerable fixture (0/100)"),
            ("/clear", "clear terminal screen"),
            ("/help", "display this reference"),
            ("/exit", "exit session"),
        ]
        for cmd, desc in commands:
            print(f"  {PRIMARY}{cmd:<15}{RESET} {FAINT}{desc}{RESET}")
        print()

        print(f"{DIM}shortcuts{RESET}")
        shortcuts = [
            ("↑↓", "navigate menu"),
            ("tab", "complete selected command"),
            ("enter", "run command"),
            ("ctrl+c", "exit immediately"),
        ]
        for key, desc in shortcuts:
            print(f"  {PRIMARY}{key:<15}{RESET} {FAINT}{desc}{RESET}")
        print()

        cls.print_next_step(command_type="help")


def print_scan_result(
    result: ScanResult,
    min_severity: Severity = Severity.INFO,
    compact: bool = False,
    fancy: bool = False,
    no_anim: bool = False,
) -> None:
    ConsoleReporter.print_result(
        result=result,
        min_severity=min_severity,
        compact=compact,
        fancy=fancy,
        no_anim=no_anim,
    )


def print_header(result: Optional[ScanResult] = None, fancy: bool = True) -> None:
    ConsoleReporter.print_header(result=result)


def print_help(fancy: bool = True) -> None:
    ConsoleReporter.print_help(utf8=fancy)


class InteractivePrompt:
    """Minimal unboxed slash command menu with keyboard navigation."""

    COMMANDS = [
        ("/scan", "scan codebase pre-deploy"),
        ("/abom", "bill of materials & mcp inventory"),
        ("/compliance", "imda & owasp matrix"),
        ("/secure", "benchmark · secure fixture"),
        ("/vulnerable", "benchmark · vulnerable fixture"),
    ]

    @classmethod
    def get_filtered(cls, text: str) -> List[tuple[str, str]]:
        clean = text.strip()
        if not clean or clean in ("/", "/scan"):
            return cls.COMMANDS
        if clean.startswith("/"):
            matches = [c for c in cls.COMMANDS if c[0].startswith(clean)]
            if matches:
                return matches
        matches = [c for c in cls.COMMANDS if clean in c[0] or clean in c[1].lower()]
        if matches:
            return matches
        return [(clean, "custom command")]

    @classmethod
    def render_widget(cls, text: str, selected_idx: int, utf8: bool = True, width: Optional[int] = None) -> int:
        filtered = cls.get_filtered(text)
        selected_idx = max(0, min(selected_idx, len(filtered) - 1))

        try:
            term_cols = shutil.get_terminal_size((80, 24)).columns
        except Exception:
            term_cols = 80
        box_w = min(60, term_cols - 4)

        lines = []
        cursor_ch = "█" if utf8 else "|"
        disp_text = text if text else ""

        # ── Input box ─────────────────────────────────────────────
        # Top border of the input field
        top_border = "─" * box_w
        lines.append(f"{FAINT}  ╭{top_border}╮{RESET}")

        # Input line: › [typed text█]
        inner = f"{DIM}›{RESET} {PRIMARY}{disp_text}{RESET}{FAINT}{cursor_ch}{RESET}"
        # Visible length (strip ANSI) for padding calculation
        visible_len = 2 + len(disp_text) + 1  # "› " + text + cursor
        pad = max(0, box_w - visible_len - 1)
        lines.append(f"{FAINT}  │{RESET} {inner}{' ' * pad}{FAINT}│{RESET}")

        # Bottom border of input field
        lines.append(f"{FAINT}  ╰{top_border}╯{RESET}")
        lines.append("")

        # ── Command suggestions ────────────────────────────────────
        cmd_col_w = 13
        for idx, (cmd, desc) in enumerate(filtered):
            if idx == selected_idx:
                row = f"  {ACCENT}›{RESET} {ACCENT}{cmd:<{cmd_col_w}}{RESET} {DIM}{desc}{RESET}"
            else:
                row = f"    {DIM}{cmd:<{cmd_col_w}}{RESET} {FAINT}{desc}{RESET}"
            lines.append(row)

        lines.append("")
        hint = "↑↓ navigate   tab complete   ⏎ run   ctrl+c exit"
        lines.append(f"  {FAINT}{hint}{RESET}")

        total_lines = len(lines)
        output_str = "\033[?25l" + "\n".join(lines)
        sys.stdout.write(output_str)
        sys.stdout.flush()
        return total_lines

    @classmethod
    def ask(cls, initial_text: str = "/scan", utf8: bool = True) -> str:
        """Prompts interactively with live keyboard navigation."""
        if not sys.stdin.isatty():
            try:
                return input().strip()
            except (EOFError, KeyboardInterrupt):
                return "exit"

        is_windows = os.name == "nt"
        if is_windows:
            try:
                import msvcrt
            except ImportError:
                is_windows = False

        text = initial_text
        selected_idx = 0
        total_lines_rendered = 0

        def redraw():
            nonlocal total_lines_rendered
            if total_lines_rendered > 0:
                # Move cursor back up and clear
                up = total_lines_rendered - 1
                sys.stdout.write(f"\r\033[{up}A\033[J")
            total_lines_rendered = cls.render_widget(text, selected_idx, utf8=utf8)

        def clear_and_finish(chosen_cmd: str):
            nonlocal total_lines_rendered
            if total_lines_rendered > 0:
                up = total_lines_rendered - 1
                sys.stdout.write(f"\r\033[{up}A\033[J")
            sys.stdout.write(f"\033[?25h{DIM}›{RESET} {PRIMARY}{chosen_cmd}{RESET}\n\n")
            sys.stdout.flush()

        old_set = None
        fd = None
        if not is_windows:
            try:
                import tty, termios
                fd = sys.stdin.fileno()
                old_set = termios.tcgetattr(fd)
                tty.setcbreak(fd)
            except Exception:
                old_set = None

        redraw()

        try:
            while True:
                key = None
                if is_windows:
                    if msvcrt.kbhit():
                        ch = msvcrt.getwch()
                        if ch in ("\x00", "\xe0"):
                            code = msvcrt.getwch()
                            if code == "H": key = "UP"
                            elif code == "P": key = "DOWN"
                        elif ch in ("\r", "\n"):
                            key = "ENTER"
                        elif ch == "\t":
                            key = "TAB"
                        elif ch in ("\x08", "\x7f"):
                            key = "BACKSPACE"
                        elif ch == "\x03":
                            key = "CTRL_C"
                        elif ch in ("\x04", "\x1a"):
                            key = "CTRL_D"
                        elif ch == "\x1b":
                            key = "ESC"
                        elif ch.isprintable():
                            key = ch
                    else:
                        time.sleep(0.02)
                else:
                    import select
                    r, _, _ = select.select([sys.stdin], [], [], 0.02)
                    if r:
                        ch = sys.stdin.read(1)
                        if ch == "\x1b":
                            r2, _, _ = select.select([sys.stdin], [], [], 0.03)
                            if r2:
                                seq = sys.stdin.read(2)
                                if seq == "[A": key = "UP"
                                elif seq == "[B": key = "DOWN"
                            else:
                                key = "ESC"
                        elif ch in ("\r", "\n"): key = "ENTER"
                        elif ch == "\t": key = "TAB"
                        elif ch in ("\x7f", "\x08"): key = "BACKSPACE"
                        elif ch == "\x03": key = "CTRL_C"
                        elif ch in ("\x04", "\x1a"): key = "CTRL_D"
                        elif ch.isprintable(): key = ch

                if key is None:
                    continue

                if key == "CTRL_C":
                    if total_lines_rendered > 0:
                        up = total_lines_rendered - 1
                        sys.stdout.write(f"\r\033[{up}A\033[J")
                    sys.stdout.write(f"\033[?25h\033[0m\n{DIM}cancelled{RESET}\n")
                    sys.stdout.flush()
                    raise KeyboardInterrupt

                if key == "CTRL_D":
                    clear_and_finish("exit")
                    return "exit"

                if key == "ENTER":
                    filtered = cls.get_filtered(text)
                    if not text.strip() or text.strip() in ("/", "/scan"):
                        chosen = filtered[selected_idx][0] if filtered else "/scan"
                    else:
                        chosen = text.strip()
                    clear_and_finish(chosen)
                    return chosen

                if key == "TAB":
                    filtered = cls.get_filtered(text)
                    if filtered and 0 <= selected_idx < len(filtered):
                        text = filtered[selected_idx][0]
                        selected_idx = 0
                    redraw()
                    continue

                if key == "UP":
                    filtered = cls.get_filtered(text)
                    if filtered:
                        selected_idx = (selected_idx - 1) % len(filtered)
                    redraw()
                    continue

                if key == "DOWN":
                    filtered = cls.get_filtered(text)
                    if filtered:
                        selected_idx = (selected_idx + 1) % len(filtered)
                    redraw()
                    continue

                if key == "BACKSPACE":
                    text = text[:-1]
                    selected_idx = 0
                    redraw()
                    continue

                if key == "ESC":
                    text = ""
                    selected_idx = 0
                    redraw()
                    continue

                if len(key) == 1 and key.isprintable():
                    text += key
                    selected_idx = 0
                    redraw()
                    continue
        finally:
            if not is_windows and old_set is not None and fd is not None:
                try:
                    import termios
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_set)
                except Exception:
                    pass
            reset_terminal()
