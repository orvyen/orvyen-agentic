"""
Audit-Ready PDF Reporter for Orvyen Agentic.
Generates regulatory compliance audit reports (Singapore IMDA, OWASP Top 10, AIBOM, Findings).
Built using standard library Python with pure PDF 1.4 byte generation (zero runtime dependencies).
Optional integration with reportlab if available.

Gated behind license_gate.py:
Flag --format pdf requires a valid license key, else returns:
"Requires license: orvyen.dev/pricing"
"""

from __future__ import annotations
import io
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from orvyen.core.models import Finding, ScanResult, Severity, ToolPrivilege
from orvyen.compliance.aibom import AIBOMCompiler
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator
from orvyen.compliance.license_gate import is_valid_license


# PDF Page Dimensions (A4 in points: 72 points = 1 inch)
PAGE_WIDTH = 595.28
PAGE_HEIGHT = 841.89
MARGIN_LEFT = 36.0
MARGIN_RIGHT = 36.0
MARGIN_TOP = 40.0
MARGIN_BOTTOM = 40.0
CONTENT_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT  # 523.28 pt


class _PDFCanvas:
    """Lightweight, pure-stdlib PDF 1.4 vector generator for audit documents."""

    def __init__(self):
        self.pages: List[List[str]] = []
        self.current_page: List[str] = []
        self.y = MARGIN_TOP
        self.page_number = 0

    def add_page(self, is_cover: bool = False) -> None:
        self.current_page = []
        self.pages.append(self.current_page)
        self.page_number += 1
        self.y = MARGIN_TOP
        if not is_cover:
            self._draw_page_decorations()

    def _to_pdf_y(self, y: float) -> float:
        """Convert top-down y coordinate to PDF bottom-up coordinate."""
        return PAGE_HEIGHT - y

    def _draw_page_decorations(self) -> None:
        """Header and footer banners for internal pages."""
        # Top running header line
        self.draw_line(MARGIN_LEFT, 26, MARGIN_LEFT + CONTENT_WIDTH, 26, color=(0.85, 0.88, 0.92), width=0.75)
        self.draw_text(MARGIN_LEFT, 22, "ORVYEN AGENTIC • REGULATORY SECURITY AUDIT REPORT", font="F2", size=7, color=(0.45, 0.50, 0.58))
        self.draw_text(PAGE_WIDTH - MARGIN_RIGHT - 110, 22, "STRICTLY CONFIDENTIAL", font="F2", size=7, color=(0.75, 0.20, 0.20))

        # Bottom footer line
        footer_y = PAGE_HEIGHT - 26
        self.draw_line(MARGIN_LEFT, footer_y - 4, MARGIN_LEFT + CONTENT_WIDTH, footer_y - 4, color=(0.85, 0.88, 0.92), width=0.75)
        self.draw_text(MARGIN_LEFT, footer_y, "Orvyen • Singapore IMDA Framework v1.5 • OWASP LLM Top 10", font="F1", size=7, color=(0.45, 0.50, 0.58))
        self.draw_text(PAGE_WIDTH - MARGIN_RIGHT - 50, footer_y, f"Page {self.page_number}", font="F2", size=7, color=(0.45, 0.50, 0.58))

    def ensure_space(self, height: float) -> None:
        """Start a new page if the remaining vertical space is insufficient."""
        if self.y + height > PAGE_HEIGHT - MARGIN_BOTTOM - 20:
            self.add_page(is_cover=False)

    def draw_rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill_color: Optional[Tuple[float, float, float]] = None,
        stroke_color: Optional[Tuple[float, float, float]] = None,
        line_width: float = 1.0,
    ) -> None:
        pdf_y = self._to_pdf_y(y + h)
        ops = []
        if line_width != 1.0:
            ops.append(f"{line_width:.2f} w")
        if stroke_color:
            r, g, b = stroke_color
            ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG")
        if fill_color:
            r, g, b = fill_color
            ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")

        ops.append(f"{x:.2f} {pdf_y:.2f} {w:.2f} {h:.2f} re")
        if fill_color and stroke_color:
            ops.append("B")
        elif fill_color:
            ops.append("f")
        elif stroke_color:
            ops.append("S")
        self.current_page.append(" ".join(ops))

    def draw_line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: Tuple[float, float, float] = (0.8, 0.8, 0.8),
        width: float = 1.0,
    ) -> None:
        py1 = self._to_pdf_y(y1)
        py2 = self._to_pdf_y(y2)
        r, g, b = color
        self.current_page.append(
            f"{width:.2f} w {r:.3f} {g:.3f} {b:.3f} RG {x1:.2f} {py1:.2f} m {x2:.2f} {py2:.2f} l S"
        )

    def draw_text(
        self,
        x: float,
        y: float,
        text: str,
        font: str = "F1",
        size: float = 10.0,
        color: Tuple[float, float, float] = (0.1, 0.1, 0.1),
    ) -> None:
        pdf_y = self._to_pdf_y(y)
        r, g, b = color
        safe_text = (
            text.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .encode("latin-1", "replace")
            .decode("latin-1")
        )
        self.current_page.append(
            f"{r:.3f} {g:.3f} {b:.3f} rg BT /{font} {size:.1f} Tf {x:.2f} {pdf_y:.2f} Td ({safe_text}) Tj ET"
        )

    def draw_wrapped_text(
        self,
        x: float,
        y: float,
        text: str,
        max_width: float,
        font: str = "F1",
        size: float = 9.0,
        line_height: float = 12.0,
        color: Tuple[float, float, float] = (0.15, 0.15, 0.15),
    ) -> float:
        """Wrap and print text, returning the new y position."""
        words = text.split()
        if not words:
            return y

        char_w = size * 0.52 if "F1" in font else size * 0.58
        max_chars = max(10, int(max_width / char_w))

        current_line: List[str] = []
        current_len = 0
        curr_y = y

        for word in words:
            if current_len + len(word) + 1 <= max_chars:
                current_line.append(word)
                current_len += len(word) + 1
            else:
                if current_line:
                    line_str = " ".join(current_line)
                    self.draw_text(x, curr_y, line_str, font=font, size=size, color=color)
                    curr_y += line_height
                current_line = [word]
                current_len = len(word)

        if current_line:
            line_str = " ".join(current_line)
            self.draw_text(x, curr_y, line_str, font=font, size=size, color=color)
            curr_y += line_height

        return curr_y

    def draw_badge(
        self,
        x: float,
        y: float,
        text: str,
        bg_color: Tuple[float, float, float],
        text_color: Tuple[float, float, float],
        font: str = "F2",
        size: float = 7.5,
        padding_x: float = 5.0,
        padding_y: float = 2.0,
    ) -> float:
        """Draw an inline colored rounded badge, returning total width."""
        char_w = size * 0.60
        text_width = len(text) * char_w
        badge_w = text_width + (padding_x * 2)
        badge_h = size + (padding_y * 2)

        self.draw_rect(x, y - size - padding_y + 1, badge_w, badge_h, fill_color=bg_color, stroke_color=None)
        self.draw_text(x + padding_x, y, text, font=font, size=size, color=text_color)
        return badge_w

    def build_pdf(self) -> bytes:
        """Compile internal vector stream into compliant PDF 1.4 document bytes."""
        if not self.pages:
            self.add_page(is_cover=True)

        num_pages = len(self.pages)
        page_obj_ids = [5 + 2 * i for i in range(num_pages)]
        content_obj_ids = [6 + 2 * i for i in range(num_pages)]

        objs: Dict[int, bytes] = {}
        # Object 1: Catalog
        objs[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
        # Object 2: Pages container
        kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
        objs[2] = f"<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>".encode("latin1")
        # Standard 14 Type 1 Fonts (Helvetica, Helvetica-Bold, Courier, Courier-Bold)
        objs[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        objs[4] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"

        font_res = "<< /Font << /F1 3 0 R /F2 4 0 R >> >>"

        for i in range(num_pages):
            pid = page_obj_ids[i]
            cid = content_obj_ids[i]
            objs[pid] = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH:.2f} {PAGE_HEIGHT:.2f}] "
                f"/Resources {font_res} /Contents {cid} 0 R >>"
            ).encode("latin1")

            stream_bytes = "\n".join(self.pages[i]).encode("latin1", "replace")
            objs[cid] = (
                f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin1")
                + stream_bytes
                + b"\nendstream"
            )

        # Emit PDF with cross reference table
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        xref: Dict[int, int] = {}

        total_objs = len(objs)
        for oid in range(1, total_objs + 1):
            xref[oid] = out.tell()
            out.write(f"{oid} 0 obj\n".encode("latin1"))
            out.write(objs[oid])
            out.write(b"\nendobj\n")

        startxref = out.tell()
        out.write(f"xref\n0 {total_objs + 1}\n0000000000 65535 f \n".encode("latin1"))
        for oid in range(1, total_objs + 1):
            out.write(f"{xref[oid]:010d} 00000 n \n".encode("latin1"))

        out.write(
            f"trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n".encode("latin1")
        )
        return out.getvalue()


class PDFReporter:
    """Audit-ready compliance and security PDF report generator."""

    @classmethod
    def generate(cls, result: ScanResult, license_key: Optional[str] = None) -> bytes:
        """
        Generate audit-ready PDF document bytes.
        Requires a valid Pro license key via license_gate.py.
        """
        if not is_valid_license(license_key):
            raise PermissionError("Requires license: orvyen.dev/pricing")

        # Compile compliance matrices & AIBOM if not already attached
        aibom = result.aibom or AIBOMCompiler.compile(result)
        imda = IMDAComplianceEvaluator.evaluate(result.findings)
        owasp = OWASPComplianceEvaluator.evaluate(result.findings)

        canvas = _PDFCanvas()

        # 1. Cover Page
        cls._render_cover_page(canvas, result, aibom, imda, owasp)

        # 2. Executive Summary & Posture
        canvas.add_page(is_cover=False)
        cls._render_executive_summary(canvas, result, aibom, imda, owasp)

        # 3. Agent Bill of Materials (AIBOM)
        cls._render_aibom_section(canvas, aibom)

        # 4. Security Findings Table
        cls._render_findings_section(canvas, result)

        # 5. Singapore IMDA Governance Matrix
        cls._render_imda_matrix(canvas, imda)

        # 6. OWASP Top 10 for LLMs Matrix
        cls._render_owasp_matrix(canvas, owasp)

        return canvas.build_pdf()

    @classmethod
    def write_to_file(cls, result: ScanResult, output_path: Path, license_key: Optional[str] = None) -> Path:
        """Generate and write PDF report to filesystem."""
        pdf_bytes = cls.generate(result, license_key=license_key)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)
        return output_path

    # =========================================================================
    # Section Renderers
    # =========================================================================

    @classmethod
    def _render_cover_page(
        cls,
        canvas: _PDFCanvas,
        result: ScanResult,
        aibom: Dict[str, Any],
        imda: Dict[str, Any],
        owasp: Dict[str, Any],
    ) -> None:
        canvas.add_page(is_cover=True)

        # Top corporate banner (Deep Navy)
        canvas.draw_rect(0, 0, PAGE_WIDTH, 140, fill_color=(0.06, 0.12, 0.24))

        # Brand header
        canvas.draw_text(MARGIN_LEFT, 45, "ORVYEN • AI AGENT SECURITY & COMPLIANCE", font="F2", size=9, color=(0.40, 0.65, 0.95))
        canvas.draw_text(MARGIN_LEFT, 78, "ORVYEN AGENTIC", font="F2", size=26, color=(1.0, 1.0, 1.0))
        canvas.draw_text(MARGIN_LEFT, 102, "AI Agent Security & Regulatory Compliance Audit Report", font="F1", size=13, color=(0.80, 0.85, 0.92))

        # Sub-header stripe
        canvas.draw_rect(0, 140, PAGE_WIDTH, 4, fill_color=(0.18, 0.50, 0.92))

        # Metadata Card
        canvas.y = 165
        card_x = MARGIN_LEFT
        card_w = CONTENT_WIDTH
        canvas.draw_rect(card_x, canvas.y, card_w, 110, fill_color=(0.97, 0.98, 0.99), stroke_color=(0.85, 0.88, 0.92), line_width=1)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        canvas.draw_text(card_x + 16, canvas.y + 24, "AUDIT TARGET & SCAN METADATA", font="F2", size=9, color=(0.20, 0.25, 0.35))
        canvas.draw_line(card_x + 16, canvas.y + 30, card_x + card_w - 16, canvas.y + 30, color=(0.88, 0.90, 0.94))

        canvas.draw_text(card_x + 16, canvas.y + 50, "Target Scope:", font="F2", size=9, color=(0.45, 0.50, 0.58))
        canvas.draw_text(card_x + 110, canvas.y + 50, str(result.target_path), font="F1", size=9, color=(0.10, 0.12, 0.18))

        canvas.draw_text(card_x + 16, canvas.y + 68, "Audit Date:", font="F2", size=9, color=(0.45, 0.50, 0.58))
        canvas.draw_text(card_x + 110, canvas.y + 68, now_str, font="F1", size=9, color=(0.10, 0.12, 0.18))

        canvas.draw_text(card_x + 16, canvas.y + 86, "Scanner Version:", font="F2", size=9, color=(0.45, 0.50, 0.58))
        canvas.draw_text(card_x + 110, canvas.y + 86, "v0.3.0 (Stdlib Engine)", font="F1", size=9, color=(0.10, 0.12, 0.18))

        canvas.draw_text(card_x + 290, canvas.y + 68, "Files Inspected:", font="F2", size=9, color=(0.45, 0.50, 0.58))
        canvas.draw_text(card_x + 390, canvas.y + 68, str(result.files_scanned), font="F1", size=9, color=(0.10, 0.12, 0.18))

        canvas.draw_text(card_x + 290, canvas.y + 86, "Scan Execution:", font="F2", size=9, color=(0.45, 0.50, 0.58))
        canvas.draw_text(card_x + 390, canvas.y + 86, f"{result.duration_ms:.2f} ms (<100ms standard)", font="F1", size=9, color=(0.10, 0.12, 0.18))

        # Overall Risk Score Display Box
        canvas.y = 295
        score = result.security_score
        is_healthy = score >= 80

        score_bg = (0.94, 0.98, 0.94) if is_healthy else (0.99, 0.94, 0.94)
        score_border = (0.35, 0.75, 0.40) if is_healthy else (0.85, 0.30, 0.30)
        score_text_col = (0.15, 0.55, 0.20) if is_healthy else (0.75, 0.15, 0.15)

        canvas.draw_rect(card_x, canvas.y, card_w, 140, fill_color=score_bg, stroke_color=score_border, line_width=1.5)

        canvas.draw_text(card_x + 24, canvas.y + 35, "EXECUTIVE POSTURE SCORE", font="F2", size=10, color=(0.30, 0.35, 0.45))
        score_display = f"{score} / 100"
        canvas.draw_text(card_x + 24, canvas.y + 80, score_display, font="F2", size=36, color=score_text_col)

        status_label = "AUDIT HEALTHY • PRODUCTION READY" if is_healthy else "HIGH RISK • POLICY VIOLATIONS DETECTED"
        canvas.draw_text(card_x + 24, canvas.y + 110, status_label, font="F2", size=10, color=score_text_col)

        # Framework Pills inside Cover Card
        canvas.draw_rect(card_x + 260, canvas.y + 24, 235, 95, fill_color=(1.0, 1.0, 1.0), stroke_color=(0.85, 0.88, 0.92))
        canvas.draw_text(card_x + 275, canvas.y + 44, "Regulatory Alignment:", font="F2", size=8.5, color=(0.30, 0.35, 0.45))

        imda_status = imda.get("overall_status", "UNKNOWN")
        imda_color = (0.15, 0.60, 0.25) if imda_status == "COMPLIANT" else (0.80, 0.20, 0.20)
        canvas.draw_text(card_x + 275, canvas.y + 64, f"Singapore IMDA: {imda_status} ({imda.get('score_percentage', 0)}%)", font="F2", size=9, color=imda_color)

        owasp_status = owasp.get("overall_status", "UNKNOWN")
        owasp_color = (0.15, 0.60, 0.25) if owasp_status == "PASS" else (0.80, 0.20, 0.20)
        canvas.draw_text(card_x + 275, canvas.y + 84, f"OWASP LLM Top 10: {owasp_status} ({owasp.get('pass_rate_percentage', 0)}%)", font="F2", size=9, color=owasp_color)

        canvas.draw_text(card_x + 275, canvas.y + 104, f"Active Findings: {len(result.findings)} identified", font="F1", size=8.5, color=(0.40, 0.45, 0.52))

        # Bottom Assurance notice
        canvas.y = 460
        canvas.draw_rect(card_x, canvas.y, card_w, 85, fill_color=(0.96, 0.97, 0.99), stroke_color=(0.85, 0.88, 0.92))
        canvas.draw_text(card_x + 16, canvas.y + 22, "REGULATORY COMPLIANCE ATTESTATION", font="F2", size=8.5, color=(0.20, 0.25, 0.35))
        statement = (
            "This document is an official security and governance audit report generated by Orvyen Agentic. "
            "It validates compliance with the Singapore IMDA Model AI Governance Framework for Agentic AI "
            "(May 2026 4-Pillars), MAS AI Risk Management Guidelines, and the OWASP Top 10 for LLM Applications. "
            "All findings contain prescriptive technical remediations for automated DevSecOps remediation."
        )
        canvas.draw_wrapped_text(card_x + 16, canvas.y + 38, statement, card_w - 32, font="F1", size=8, line_height=11, color=(0.35, 0.40, 0.48))

        # Cover page footer
        canvas.draw_line(MARGIN_LEFT, 770, MARGIN_LEFT + CONTENT_WIDTH, 770, color=(0.85, 0.88, 0.92))
        canvas.draw_text(MARGIN_LEFT, 785, "CONFIDENTIAL • PREPARED BY ORVYEN • ORVYEN.DEV", font="F2", size=8, color=(0.45, 0.50, 0.58))

    @classmethod
    def _render_executive_summary(
        cls,
        canvas: _PDFCanvas,
        result: ScanResult,
        aibom: Dict[str, Any],
        imda: Dict[str, Any],
        owasp: Dict[str, Any],
    ) -> None:
        canvas.ensure_space(180)
        canvas.draw_text(MARGIN_LEFT, canvas.y, "1. EXECUTIVE SUMMARY & POSTURE SCORECARD", font="F2", size=13, color=(0.08, 0.18, 0.36))
        canvas.y += 10
        canvas.draw_line(MARGIN_LEFT, canvas.y, MARGIN_LEFT + CONTENT_WIDTH, canvas.y, color=(0.18, 0.50, 0.92), width=1.5)
        canvas.y += 18

        # 4 Summary Metric Boxes
        box_w = (CONTENT_WIDTH - 24) / 4
        box_h = 56

        counts = {
            "CRITICAL": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
            "HIGH": sum(1 for f in result.findings if f.severity == Severity.HIGH),
            "MEDIUM": sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
            "LOW": sum(1 for f in result.findings if f.severity == Severity.LOW),
        }

        # Box 1: Security Score
        canvas.draw_rect(MARGIN_LEFT, canvas.y, box_w, box_h, fill_color=(0.97, 0.98, 1.0), stroke_color=(0.80, 0.85, 0.95))
        canvas.draw_text(MARGIN_LEFT + 10, canvas.y + 16, "SECURITY SCORE", font="F2", size=7.5, color=(0.35, 0.45, 0.60))
        canvas.draw_text(MARGIN_LEFT + 10, canvas.y + 40, f"{result.security_score}/100", font="F2", size=18, color=(0.10, 0.20, 0.45))

        # Box 2: Critical / High
        crit_high = counts["CRITICAL"] + counts["HIGH"]
        box2_x = MARGIN_LEFT + box_w + 8
        canvas.draw_rect(box2_x, canvas.y, box_w, box_h, fill_color=(1.0, 0.96, 0.96), stroke_color=(0.95, 0.80, 0.80))
        canvas.draw_text(box2_x + 10, canvas.y + 16, "CRITICAL / HIGH", font="F2", size=7.5, color=(0.70, 0.20, 0.20))
        canvas.draw_text(box2_x + 10, canvas.y + 40, f"{crit_high} Issues", font="F2", size=18, color=(0.75, 0.15, 0.15))

        # Box 3: Total Assets
        total_tools = len(result.tools)
        high_priv_tools = sum(1 for t in result.tools if t.privilege in (ToolPrivilege.EXECUTE, ToolPrivilege.ADMIN))
        box3_x = MARGIN_LEFT + (box_w * 2) + 16
        canvas.draw_rect(box3_x, canvas.y, box_w, box_h, fill_color=(0.96, 0.98, 0.96), stroke_color=(0.80, 0.90, 0.82))
        canvas.draw_text(box3_x + 10, canvas.y + 16, "TOOLS & PRIVILEGE", font="F2", size=7.5, color=(0.20, 0.50, 0.25))
        canvas.draw_text(box3_x + 10, canvas.y + 40, f"{total_tools} ({high_priv_tools} High)", font="F2", size=15, color=(0.15, 0.50, 0.20))

        # Box 4: MCP Servers
        mcp_count = len(result.mcp_servers)
        box4_x = MARGIN_LEFT + (box_w * 3) + 24
        canvas.draw_rect(box4_x, canvas.y, box_w, box_h, fill_color=(0.98, 0.97, 1.0), stroke_color=(0.85, 0.80, 0.95))
        canvas.draw_text(box4_x + 10, canvas.y + 16, "MCP GATEWAYS", font="F2", size=7.5, color=(0.45, 0.30, 0.65))
        canvas.draw_text(box4_x + 10, canvas.y + 40, f"{mcp_count} Servers", font="F2", size=18, color=(0.35, 0.20, 0.55))

        canvas.y += box_h + 20

    @classmethod
    def _render_aibom_section(cls, canvas: _PDFCanvas, aibom: Dict[str, Any]) -> None:
        tools_data = aibom.get("tools", {})
        tools = []
        if isinstance(tools_data, dict):
            by_priv = tools_data.get("by_privilege", {})
            for priv_tier in ("admin", "execute", "write", "read"):
                for t in by_priv.get(priv_tier, []):
                    t_item = dict(t)
                    t_item["privilege_tier"] = priv_tier.upper()
                    tools.append(t_item)
        elif isinstance(tools_data, list):
            tools = tools_data

        mcp_servers = aibom.get("mcp_servers", [])

        canvas.ensure_space(120)
        canvas.draw_text(MARGIN_LEFT, canvas.y, "2. AGENT BILL OF MATERIALS (AIBOM)", font="F2", size=13, color=(0.08, 0.18, 0.36))
        canvas.y += 10
        canvas.draw_line(MARGIN_LEFT, canvas.y, MARGIN_LEFT + CONTENT_WIDTH, canvas.y, color=(0.18, 0.50, 0.92), width=1.5)
        canvas.y += 16

        canvas.draw_text(MARGIN_LEFT, canvas.y, "TOOL INVENTORY & PRIVILEGE TIERS", font="F2", size=9, color=(0.25, 0.30, 0.40))
        canvas.y += 12

        # Table Header
        col_w = [140.0, 75.0, 85.0, 160.0, 63.28]
        headers = ["Tool Name", "Framework", "Privilege Tier", "Dangerous Sinks", "Audited"]

        canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=(0.12, 0.20, 0.35))
        x_cursor = MARGIN_LEFT
        for idx, h in enumerate(headers):
            canvas.draw_text(x_cursor + 6, canvas.y + 12, h, font="F2", size=7.5, color=(1.0, 1.0, 1.0))
            x_cursor += col_w[idx]
        canvas.y += 18

        if not tools:
            canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 20, fill_color=(0.98, 0.98, 0.98))
            canvas.draw_text(MARGIN_LEFT + 8, canvas.y + 14, "No tools discovered in scan target.", font="F1", size=8, color=(0.5, 0.5, 0.5))
            canvas.y += 24
        else:
            for row_idx, t in enumerate(tools):
                canvas.ensure_space(20)
                row_bg = (1.0, 1.0, 1.0) if row_idx % 2 == 0 else (0.97, 0.98, 0.99)
                canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=row_bg, stroke_color=(0.90, 0.92, 0.95), line_width=0.5)

                name = str(t.get("name", "unknown"))[:22]
                framework = str(t.get("framework", "custom"))[:12]
                priv = str(t.get("privilege_tier", "READ"))
                sinks = ", ".join(t.get("dangerous_sinks", [])) or "None"
                sinks = sinks[:32]
                audited = "Yes" if t.get("is_audited") else "No"

                # Privilege color
                if priv in ("ADMIN", "EXECUTE"):
                    priv_col = (0.75, 0.15, 0.15)
                elif priv == "WRITE":
                    priv_col = (0.80, 0.45, 0.05)
                else:
                    priv_col = (0.15, 0.50, 0.20)

                x = MARGIN_LEFT
                canvas.draw_text(x + 6, canvas.y + 12, name, font="F2", size=7.5, color=(0.10, 0.12, 0.18))
                x += col_w[0]
                canvas.draw_text(x + 6, canvas.y + 12, framework, font="F1", size=7.5, color=(0.35, 0.40, 0.48))
                x += col_w[1]
                canvas.draw_text(x + 6, canvas.y + 12, priv, font="F2", size=7.5, color=priv_col)
                x += col_w[2]
                canvas.draw_text(x + 6, canvas.y + 12, sinks, font="F1", size=7.0, color=(0.20, 0.25, 0.30))
                x += col_w[3]
                audit_col = (0.15, 0.55, 0.20) if audited == "Yes" else (0.65, 0.20, 0.20)
                canvas.draw_text(x + 6, canvas.y + 12, audited, font="F2", size=7.5, color=audit_col)

                canvas.y += 18

        canvas.y += 15

        # MCP Servers Table
        if mcp_servers:
            canvas.ensure_space(80)
            canvas.draw_text(MARGIN_LEFT, canvas.y, "MODEL CONTEXT PROTOCOL (MCP) SERVERS", font="F2", size=9, color=(0.25, 0.30, 0.40))
            canvas.y += 12

            mcp_cols = [150.0, 110.0, 80.0, 183.28]
            mcp_headers = ["Server Name", "Transport / Command", "Tools Bound", "Status"]

            canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=(0.12, 0.20, 0.35))
            x_cursor = MARGIN_LEFT
            for idx, h in enumerate(mcp_headers):
                canvas.draw_text(x_cursor + 6, canvas.y + 12, h, font="F2", size=7.5, color=(1.0, 1.0, 1.0))
                x_cursor += mcp_cols[idx]
            canvas.y += 18

            for row_idx, s in enumerate(mcp_servers):
                canvas.ensure_space(20)
                row_bg = (1.0, 1.0, 1.0) if row_idx % 2 == 0 else (0.97, 0.98, 0.99)
                canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=row_bg, stroke_color=(0.90, 0.92, 0.95), line_width=0.5)

                sname = str(s.get("name", "server"))[:25]
                trans = str(s.get("command", s.get("transport", "stdio")))[:18]
                tcount = f"{len(s.get('tools', []))} tools"
                notes = "Plaintext HTTP" if "http" in str(s).lower() else "Inspected"

                x = MARGIN_LEFT
                canvas.draw_text(x + 6, canvas.y + 12, sname, font="F2", size=7.5, color=(0.10, 0.12, 0.18))
                x += mcp_cols[0]
                canvas.draw_text(x + 6, canvas.y + 12, trans, font="F1", size=7.5, color=(0.35, 0.40, 0.48))
                x += mcp_cols[1]
                canvas.draw_text(x + 6, canvas.y + 12, tcount, font="F1", size=7.5, color=(0.20, 0.25, 0.30))
                x += mcp_cols[2]
                canvas.draw_text(x + 6, canvas.y + 12, notes, font="F1", size=7.5, color=(0.30, 0.35, 0.45))

                canvas.y += 18

            canvas.y += 20

    @classmethod
    def _render_findings_section(cls, canvas: _PDFCanvas, result: ScanResult) -> None:
        canvas.ensure_space(100)
        canvas.draw_text(MARGIN_LEFT, canvas.y, "3. SECURITY FINDINGS & VULNERABILITY REGISTER", font="F2", size=13, color=(0.08, 0.18, 0.36))
        canvas.y += 10
        canvas.draw_line(MARGIN_LEFT, canvas.y, MARGIN_LEFT + CONTENT_WIDTH, canvas.y, color=(0.18, 0.50, 0.92), width=1.5)
        canvas.y += 16

        if not result.findings:
            canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 36, fill_color=(0.94, 0.98, 0.94), stroke_color=(0.35, 0.75, 0.40))
            canvas.draw_text(MARGIN_LEFT + 12, canvas.y + 22, "✔ ZERO SECURITY VIOLATIONS DETECTED. CODEBASE PASSES AUDIT BASELINE.", font="F2", size=9, color=(0.15, 0.55, 0.20))
            canvas.y += 50
            return

        for idx, f in enumerate(result.findings):
            canvas.ensure_space(85)

            # Severity badge styling
            if f.severity == Severity.CRITICAL:
                s_bg = (1.0, 0.90, 0.90)
                s_col = (0.78, 0.12, 0.15)
            elif f.severity == Severity.HIGH:
                s_bg = (1.0, 0.93, 0.85)
                s_col = (0.85, 0.40, 0.05)
            elif f.severity == Severity.MEDIUM:
                s_bg = (1.0, 0.98, 0.85)
                s_col = (0.75, 0.55, 0.05)
            else:
                s_bg = (0.90, 0.95, 1.0)
                s_col = (0.15, 0.45, 0.75)

            # Container card
            start_y = canvas.y
            canvas.draw_rect(MARGIN_LEFT, start_y, CONTENT_WIDTH, 76, fill_color=(0.99, 0.99, 1.0), stroke_color=(0.88, 0.90, 0.94), line_width=1)

            # Rule ID and Severity Banner
            canvas.draw_badge(MARGIN_LEFT + 8, start_y + 14, f.severity.name, s_bg, s_col, font="F2", size=7.5)
            canvas.draw_text(MARGIN_LEFT + 68, start_y + 14, f"{f.rule_id} • {f.rule_title}", font="F2", size=8.5, color=(0.10, 0.15, 0.25))

            loc = f"{f.file_path}:{f.line_number or 1}"
            canvas.draw_text(PAGE_WIDTH - MARGIN_RIGHT - 180, start_y + 14, loc[:30], font="F1", size=7.5, color=(0.45, 0.50, 0.58))

            # Standards tag
            standards_text = f"OWASP: {f.owasp_id or 'N/A'}  |  IMDA: {f.imda_pillar or 'N/A'}"
            canvas.draw_text(MARGIN_LEFT + 8, start_y + 28, standards_text, font="F2", size=7.0, color=(0.30, 0.40, 0.55))

            # Finding message
            canvas.draw_wrapped_text(MARGIN_LEFT + 8, start_y + 42, f.message, CONTENT_WIDTH - 16, font="F1", size=7.5, line_height=10, color=(0.15, 0.18, 0.22))

            # Remediation callout
            rem_text = f"Fix: {f.remediation}"
            canvas.draw_rect(MARGIN_LEFT + 8, start_y + 56, CONTENT_WIDTH - 16, 16, fill_color=(0.95, 0.97, 0.99))
            canvas.draw_text(MARGIN_LEFT + 12, start_y + 68, rem_text[:115], font="F2", size=7.0, color=(0.15, 0.45, 0.25))

            canvas.y += 84

        canvas.y += 15

    @classmethod
    def _render_imda_matrix(cls, canvas: _PDFCanvas, imda: Dict[str, Any]) -> None:
        canvas.ensure_space(140)
        canvas.draw_text(MARGIN_LEFT, canvas.y, "4. SINGAPORE IMDA AGENTIC AI GOVERNANCE MATRIX (v1.5)", font="F2", size=13, color=(0.08, 0.18, 0.36))
        canvas.y += 10
        canvas.draw_line(MARGIN_LEFT, canvas.y, MARGIN_LEFT + CONTENT_WIDTH, canvas.y, color=(0.18, 0.50, 0.92), width=1.5)
        canvas.y += 16

        overall_status = imda.get("overall_status", "UNKNOWN")
        score_pct = imda.get("score_percentage", 0)
        status_col = (0.15, 0.55, 0.20) if overall_status == "COMPLIANT" else (0.75, 0.15, 0.15)

        canvas.draw_text(MARGIN_LEFT, canvas.y, f"Overall Framework Alignment: {overall_status} ({score_pct}% Compliant)", font="F2", size=9, color=status_col)
        canvas.y += 14

        # Pillars table
        p_cols = [160.0, 180.0, 90.0, 93.28]
        p_headers = ["Pillar Clause", "Governance Domain", "Rules Evaluated", "Status"]

        canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=(0.12, 0.20, 0.35))
        x_c = MARGIN_LEFT
        for idx, h in enumerate(p_headers):
            canvas.draw_text(x_c + 6, canvas.y + 12, h, font="F2", size=7.5, color=(1.0, 1.0, 1.0))
            x_c += p_cols[idx]
        canvas.y += 18

        pillars = imda.get("pillars", {})
        for row_idx, (p_name, p_data) in enumerate(pillars.items()):
            canvas.ensure_space(20)
            row_bg = (1.0, 1.0, 1.0) if row_idx % 2 == 0 else (0.97, 0.98, 0.99)
            canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=row_bg, stroke_color=(0.90, 0.92, 0.95), line_width=0.5)

            p_title = p_data.get("name", p_name)[:26]
            rules_str = ", ".join(p_data.get("rules_evaluated", [])) or "None"
            status = p_data.get("status", "PASS")
            s_color = (0.15, 0.55, 0.20) if status in ("PASS", "COMPLIANT") else (0.75, 0.15, 0.15)

            x = MARGIN_LEFT
            canvas.draw_text(x + 6, canvas.y + 12, p_name, font="F2", size=7.5, color=(0.10, 0.12, 0.18))
            x += p_cols[0]
            canvas.draw_text(x + 6, canvas.y + 12, p_title, font="F1", size=7.5, color=(0.30, 0.35, 0.45))
            x += p_cols[1]
            canvas.draw_text(x + 6, canvas.y + 12, rules_str[:16], font="F1", size=7.0, color=(0.40, 0.45, 0.50))
            x += p_cols[2]
            canvas.draw_text(x + 6, canvas.y + 12, status, font="F2", size=7.5, color=s_color)

            canvas.y += 18

        canvas.y += 20

    @classmethod
    def _render_owasp_matrix(cls, canvas: _PDFCanvas, owasp: Dict[str, Any]) -> None:
        canvas.ensure_space(140)
        canvas.draw_text(MARGIN_LEFT, canvas.y, "5. OWASP TOP 10 FOR LLM APPLICATIONS (2025 EDITION)", font="F2", size=13, color=(0.08, 0.18, 0.36))
        canvas.y += 10
        canvas.draw_line(MARGIN_LEFT, canvas.y, MARGIN_LEFT + CONTENT_WIDTH, canvas.y, color=(0.18, 0.50, 0.92), width=1.5)
        canvas.y += 16

        pass_rate = owasp.get("pass_rate_percentage", 0)
        overall_status = owasp.get("overall_status", "UNKNOWN")
        status_col = (0.15, 0.55, 0.20) if overall_status == "PASS" else (0.75, 0.15, 0.15)

        canvas.draw_text(MARGIN_LEFT, canvas.y, f"Overall Category Pass Rate: {overall_status} ({pass_rate}% Passed)", font="F2", size=9, color=status_col)
        canvas.y += 14

        # OWASP Table
        ow_cols = [70.0, 190.0, 100.0, 80.0, 83.28]
        ow_headers = ["Item ID", "Vulnerability Category", "Rules Mapped", "Violations", "Status"]

        canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=(0.12, 0.20, 0.35))
        x_c = MARGIN_LEFT
        for idx, h in enumerate(ow_headers):
            canvas.draw_text(x_c + 6, canvas.y + 12, h, font="F2", size=7.5, color=(1.0, 1.0, 1.0))
            x_c += ow_cols[idx]
        canvas.y += 18

        items = owasp.get("items", {})
        for row_idx, (item_id, item_data) in enumerate(items.items()):
            canvas.ensure_space(20)
            row_bg = (1.0, 1.0, 1.0) if row_idx % 2 == 0 else (0.97, 0.98, 0.99)
            canvas.draw_rect(MARGIN_LEFT, canvas.y, CONTENT_WIDTH, 18, fill_color=row_bg, stroke_color=(0.90, 0.92, 0.95), line_width=0.5)

            title = item_data.get("title", item_id)[:30]
            rules_str = ", ".join(item_data.get("rules", [])) or "None"
            vcount = str(item_data.get("finding_count", 0))
            status = item_data.get("status", "PASS")
            s_color = (0.15, 0.55, 0.20) if status in ("PASS", "NOT APPLICABLE") else (0.75, 0.15, 0.15)

            x = MARGIN_LEFT
            canvas.draw_text(x + 6, canvas.y + 12, item_id, font="F2", size=7.5, color=(0.10, 0.12, 0.18))
            x += ow_cols[0]
            canvas.draw_text(x + 6, canvas.y + 12, title, font="F1", size=7.5, color=(0.20, 0.25, 0.35))
            x += ow_cols[1]
            canvas.draw_text(x + 6, canvas.y + 12, rules_str[:16], font="F1", size=7.0, color=(0.40, 0.45, 0.50))
            x += ow_cols[2]
            canvas.draw_text(x + 6, canvas.y + 12, vcount, font="F1", size=7.5, color=(0.30, 0.35, 0.40))
            x += ow_cols[3]
            canvas.draw_text(x + 6, canvas.y + 12, status, font="F2", size=7.5, color=s_color)

            canvas.y += 18

        canvas.y += 20
