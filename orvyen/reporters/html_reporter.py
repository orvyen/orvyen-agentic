"""
Standalone HTML report generator for Orvyen Agentic: creates interactive,
executive-ready security and compliance dashboards with embedded AIBOM.
"""

from __future__ import annotations
import html
import json
from pathlib import Path
from typing import Dict, Any

from orvyen.core.models import ScanResult
from orvyen.compliance.aibom import AIBOMCompiler


class HTMLReporter:
    """Renders self-contained, interactive HTML reports for audit and engineering review."""

    @classmethod
    def generate(cls, result: ScanResult) -> str:
        aibom = result.aibom or AIBOMCompiler.compile(result)
        imda = aibom.get("compliance", {}).get("singapore_imda", {})
        owasp = aibom.get("compliance", {}).get("owasp_llm_top10", {})
        tools = aibom.get("tools", {})
        by_priv = tools.get("by_privilege", {})
        mcp_servers = aibom.get("mcp_servers", [])

        score = result.security_score
        score_class = "score-good" if score >= 85 else ("score-warn" if score >= 60 else "score-bad")

        # Pre-render findings rows
        findings_html = []
        for f in result.findings:
            sev_class = f.severity.value.lower()
            snippet_clean = html.escape(f.code_snippet)
            findings_html.append(f"""
            <div class="finding-card finding-{sev_class}" data-severity="{f.severity.value}">
                <div class="finding-header">
                    <span class="badge badge-{sev_class}">{html.escape(f.severity.value)}</span>
                    <span class="finding-id">{html.escape(f.rule_id)}</span>
                    <h3 class="finding-title">{html.escape(f.rule_title)}</h3>
                </div>
                <div class="finding-meta">
                    <span><strong>Location:</strong> {html.escape(f.file_path)}:{f.line_number}</span>
                    <span><strong>OWASP:</strong> {html.escape(f.owasp_id)}</span>
                    <span><strong>IMDA:</strong> {html.escape(f.imda_pillar)}</span>
                </div>
                <p class="finding-msg">{html.escape(f.message)}</p>
                <div class="code-box"><pre><code>{snippet_clean}</code></pre></div>
                <div class="remediation-box">
                    <span class="rem-label">Remediation:</span>
                    <span>{html.escape(f.remediation)}</span>
                </div>
            </div>
            """)

        # Pre-render tools rows
        tools_html = []
        for priv in ("admin", "execute", "write", "read"):
            for t in by_priv.get(priv, []):
                p_class = f"badge-{priv}"
                audited = '<span class="status-yes">Yes</span>' if t.get("is_audited") else '<span class="status-no">No</span>'
                bound = '<span class="status-yes">Yes</span>' if t.get("is_bound") else '<span class="status-no">No</span>'
                sinks = html.escape(", ".join(t.get("dangerous_sinks", [])) or "None")
                tools_html.append(f"""
                <tr>
                    <td><code>{html.escape(t.get("name"))}</code></td>
                    <td><span class="badge {p_class}">{priv.upper()}</span></td>
                    <td>{html.escape(t.get("framework"))}</td>
                    <td>{audited}</td>
                    <td>{bound}</td>
                    <td><small>{sinks}</small></td>
                    <td><small>{html.escape(t.get("file_path"))}:{t.get("line_number")}</small></td>
                </tr>
                """)

        # Pre-render IMDA rows
        imda_rows = []
        for p_id, p_data in imda.get("pillars", {}).items():
            badge = '<span class="badge badge-pass">COMPLIANT</span>' if p_data.get("is_compliant") else '<span class="badge badge-fail">NON-COMPLIANT</span>'
            imda_rows.append(f"""
            <tr>
                <td><strong>{html.escape(p_id)}</strong></td>
                <td>{html.escape(p_data.get("name"))}</td>
                <td>{badge}</td>
                <td>{p_data.get("violation_count")}</td>
                <td><small>{html.escape(p_data.get("description"))}</small></td>
            </tr>
            """)

        # Pre-render OWASP rows
        owasp_rows = []
        for o_id, o_data in owasp.get("items", {}).items():
            badge = '<span class="badge badge-pass">PASS</span>' if o_data.get("is_pass") else '<span class="badge badge-fail">FAIL</span>'
            owasp_rows.append(f"""
            <tr>
                <td><strong>{html.escape(o_id)}</strong></td>
                <td>{html.escape(o_data.get("title"))}</td>
                <td>{badge}</td>
                <td>{o_data.get("violation_count")}</td>
                <td><small>{html.escape(o_data.get("description"))}</small></td>
            </tr>
            """)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orvyen Agentic Security & Compliance Report</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-heading: #f0f6fc;
            --accent: #58a6ff;
            --crit: #f85149;
            --high: #ff7b72;
            --med: #d29922;
            --low: #3fb950;
            --info: #8b949e;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 32px 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 28px;
        }}
        .brand-title {{ font-size: 26px; font-weight: 700; color: var(--text-heading); }}
        .brand-subtitle {{ font-size: 14px; color: #8b949e; margin-top: 4px; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .metric-val {{ font-size: 32px; font-weight: 700; color: var(--text-heading); margin-top: 4px; }}
        .metric-label {{ font-size: 13px; text-transform: uppercase; color: #8b949e; letter-spacing: 0.5px; }}
        .score-good {{ color: #3fb950; }}
        .score-warn {{ color: #d29922; }}
        .score-bad {{ color: #f85149; }}
        
        /* Tabs */
        .tabs {{ display: flex; gap: 12px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }}
        .tab-btn {{
            background: none;
            border: none;
            border-bottom: 2px solid transparent;
            color: #8b949e;
            font-size: 15px;
            font-weight: 600;
            padding: 12px 16px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}

        /* Finding Cards */
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            transition: border-color 0.2s;
        }}
        .finding-critical {{ border-left: 4px solid var(--crit); }}
        .finding-high {{ border-left: 4px solid var(--high); }}
        .finding-medium {{ border-left: 4px solid var(--med); }}
        .finding-low {{ border-left: 4px solid var(--low); }}
        .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }}
        .finding-title {{ font-size: 18px; color: var(--text-heading); font-weight: 600; }}
        .finding-id {{ font-size: 13px; font-family: monospace; color: #8b949e; }}
        .finding-meta {{ display: flex; flex-wrap: wrap; gap: 16px; font-size: 13px; color: #8b949e; margin-bottom: 12px; }}
        .finding-msg {{ font-size: 14px; margin-bottom: 12px; }}
        .code-box {{
            background: #090d13;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 13px;
            overflow-x: auto;
            margin-bottom: 12px;
        }}
        .remediation-box {{
            background: #1f2937;
            border-left: 3px solid var(--accent);
            padding: 10px 14px;
            border-radius: 4px;
            font-size: 13px;
        }}
        .rem-label {{ font-weight: 600; color: var(--accent); margin-right: 6px; }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #490202; color: #ff8182; border: 1px solid #da3633; }}
        .badge-high {{ background: #3d1413; color: #ff9b9b; border: 1px solid #f85149; }}
        .badge-medium {{ background: #3d2f0a; color: #e3b341; border: 1px solid #bb8009; }}
        .badge-low {{ background: #11341c; color: #56d364; border: 1px solid #238636; }}
        .badge-admin {{ background: #490202; color: #ff8182; }}
        .badge-execute {{ background: #3d1413; color: #ff9b9b; }}
        .badge-write {{ background: #3d2f0a; color: #e3b341; }}
        .badge-read {{ background: #11341c; color: #56d364; }}
        .badge-pass {{ background: #11341c; color: #56d364; }}
        .badge-fail {{ background: #3d1413; color: #ff9b9b; }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ padding: 12px 14px; border: 1px solid var(--border); text-align: left; font-size: 14px; }}
        th {{ background: #21262d; color: var(--text-heading); font-weight: 600; }}
        tr:nth-child(even) {{ background: #161b22; }}
        .status-yes {{ color: #3fb950; font-weight: 600; }}
        .status-no {{ color: #f85149; font-weight: 600; }}
        
        footer {{
            margin-top: 48px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 13px;
            color: #8b949e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1 class="brand-title">ORVYEN AGENTIC</h1>
                <p class="brand-subtitle">Static Security & Compliance Scanner for AI Agents &bull; AIBOM v1.0</p>
            </div>
            <div>
                <span class="badge badge-low">Audit Certified</span>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Security Health</div>
                <div class="metric-val {score_class}">{score} / 100</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Findings</div>
                <div class="metric-val">{result.total_findings}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Critical / High</div>
                <div class="metric-val score-bad">{result.critical_count + result.high_count}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Agent Tools Scanned</div>
                <div class="metric-val">{len(result.tools)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Singapore IMDA</div>
                <div class="metric-val {'score-good' if imda.get('score_percentage') == 100 else 'score-bad'}">{imda.get('score_percentage', 0)}%</div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="showTab('tab-findings', this)">Vulnerability Findings ({len(result.findings)})</button>
            <button class="tab-btn" onclick="showTab('tab-aibom', this)">Agent Bill of Materials (AIBOM)</button>
            <button class="tab-btn" onclick="showTab('tab-compliance', this)">Governance & Regulations</button>
        </div>

        <div id="tab-findings" class="tab-content active">
            {"".join(findings_html) if findings_html else '<p style="color: #3fb950; font-weight: 600;">No security vulnerabilities identified in target codebase.</p>'}
        </div>

        <div id="tab-aibom" class="tab-content">
            <h2 style="margin-bottom: 12px; color: var(--text-heading);">Declared Tools & Capability Permissions</h2>
            <table>
                <thead>
                    <tr>
                        <th>Tool Name</th>
                        <th>Privilege Tier</th>
                        <th>Framework</th>
                        <th>Audited</th>
                        <th>Bound</th>
                        <th>Identified Sinks</th>
                        <th>Source Location</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(tools_html) if tools_html else '<tr><td colspan="7">No tools discovered.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div id="tab-compliance" class="tab-content">
            <h2 style="margin-bottom: 12px; color: var(--text-heading);">Singapore IMDA Framework for Agentic AI (May 2026)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Pillar</th>
                        <th>Focus Name</th>
                        <th>Status</th>
                        <th>Violations</th>
                        <th>Guideline Scope</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(imda_rows)}
                </tbody>
            </table>

            <h2 style="margin-top: 32px; margin-bottom: 12px; color: var(--text-heading);">OWASP Top 10 for LLM Applications</h2>
            <table>
                <thead>
                    <tr>
                        <th>OWASP ID</th>
                        <th>Vulnerability Class</th>
                        <th>Status</th>
                        <th>Violations</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(owasp_rows)}
                </tbody>
            </table>
        </div>

        <footer>
            Generated by <strong>Orvyen Agentic</strong> &bull; Orvyen &bull; Sub-100ms Pre-Deployment Agent Security
        </footer>
    </div>

    <script>
        function showTab(tabId, btn) {{
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }}
    </script>
</body>
</html>
"""
        return html_template

    @classmethod
    def write_to_file(cls, result: ScanResult, output_path: Path) -> Path:
        content = cls.generate(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path
