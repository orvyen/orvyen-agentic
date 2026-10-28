"""
Agent Bill of Materials (AIBOM) compiler: generates auditable agent inventories
and compliance manifests in JSON and Markdown formats.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from orvyen.core.models import ScanResult, ToolPrivilege
from orvyen.compliance.imda_matrix import IMDAComplianceEvaluator
from orvyen.compliance.owasp_matrix import OWASPComplianceEvaluator
from orvyen.compliance.license_gate import is_valid_license, UPGRADE_PROMPT


class AIBOMCompiler:
    """Compiles a complete Agent Bill of Materials from static scan results."""

    @classmethod
    def compile(cls, scan_result: ScanResult) -> Dict[str, Any]:
        imda_eval = IMDAComplianceEvaluator.evaluate(scan_result.findings)
        owasp_eval = OWASPComplianceEvaluator.evaluate(scan_result.findings)

        # Categorize tools by privilege
        tools_by_privilege = {
            "admin": [],
            "execute": [],
            "write": [],
            "read": [],
        }
        # Gather bound tool names across all agents
        all_bound_names = set()
        for a in scan_result.agents:
            all_bound_names.update(a.bound_tools)

        for t in scan_result.tools:
            key = t.privilege.value.lower()
            is_bound = (
                t.is_bound
                or t.name in all_bound_names
                or t.name.replace("mcp::", "") in all_bound_names
            )
            tools_by_privilege.get(key, tools_by_privilege["read"]).append({
                "name": t.name,
                "framework": t.framework,
                "file_path": t.file_path,
                "line_number": t.line_number,
                "dangerous_sinks": t.dangerous_sinks,
                "is_audited": t.is_audited,
                "is_bound": is_bound,
            })

        # Agent architectures
        frameworks_detected = list({a.framework for a in scan_result.agents} | {t.framework for t in scan_result.tools if t.framework != "custom"})

        manifest = {
            "$schema": "https://orvyen.ai/schemas/aibom-v1.json",
            "spec_version": "1.0.0",
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "scanner": "Orvyen Agentic Static Security Engine",
                "scanner_version": "0.3.0",
                "target_path": scan_result.target_path,
                "files_scanned": scan_result.files_scanned,
                "security_score": scan_result.security_score,
                "frameworks": frameworks_detected,
            },
            "agents": [
                {
                    "name": a.name,
                    "framework": a.framework,
                    "file_path": a.file_path,
                    "line_number": a.line_number,
                    "bound_tools": a.bound_tools,
                    "recursion_limit": a.recursion_limit,
                    "step_limit": a.step_limit,
                }
                for a in scan_result.agents
            ],
            "tools": {
                "total_tools": len(scan_result.tools),
                "by_privilege": tools_by_privilege,
            },
            "mcp_servers": [
                {
                    "name": s.name,
                    "command": s.command,
                    "args": s.args,
                    "env_keys": list(s.env_vars.keys()),
                    "file_path": s.file_path,
                }
                for s in scan_result.mcp_servers
            ],
            "compliance": {
                "singapore_imda": imda_eval,
                "owasp_llm_top10": owasp_eval,
            },
            "findings_summary": {
                "total": scan_result.total_findings,
                "critical": scan_result.critical_count,
                "high": scan_result.high_count,
                "medium": scan_result.medium_count,
                "low": scan_result.low_count,
            },
        }

        return manifest

    @classmethod
    def to_markdown(
        cls,
        aibom_dict: Dict[str, Any],
        license_key: Optional[str] = None,
    ) -> str:
        """
        Render the AIBOM manifest into an audit-ready Markdown document.

        FREE:  Tool capability matrix + MCP manifest section.
        PRO:   Full IMDA/OWASP clause-mapped compliance tables.
                Requires a valid --license-key.
        """
        if not is_valid_license(license_key):
            # Free-tier output: tool matrix only, no clause mapping
            return cls._to_markdown_free(aibom_dict)
        return cls._to_markdown_pro(aibom_dict)

    @classmethod
    def _to_markdown_free(cls, aibom_dict: Dict[str, Any]) -> str:
        """Free-tier AIBOM Markdown: tool inventory only, no compliance clause tables."""
        meta = aibom_dict.get("metadata", {})
        tools = aibom_dict.get("tools", {})
        by_priv = tools.get("by_privilege", {})

        raw_target = meta.get("target_path", ".")
        try:
            from pathlib import Path
            rel_target = Path(raw_target).resolve().relative_to(Path.cwd().resolve()).as_posix()
            display_target = f"./{rel_target}" if not rel_target.startswith(".") else rel_target
        except Exception:
            display_target = Path(raw_target).as_posix()

        fw_map = {
            "mcp": "MCP Gateway",
            "langchain": "LangChain",
            "langgraph": "LangGraph",
            "crewai": "CrewAI",
        }
        raw_fws = meta.get("frameworks", [])
        formatted_fws = [fw_map.get(f.lower(), f.capitalize()) for f in raw_fws]
        fw_str = " • ".join(formatted_fws) if formatted_fws else "None"

        md = []
        md.append("# Agent Bill of Materials (AIBOM)")
        md.append("")
        md.append(f"**Target System**: `{display_target}`  ")
        md.append(f"**Generated**: {meta.get('timestamp')}  ")
        md.append(f"**Engine**: {meta.get('scanner')} v{meta.get('scanner_version')}  ")
        md.append(f"**Security Score**: **{meta.get('security_score')}/100**  ")
        md.append(f"**Frameworks Detected**: {fw_str}  ")
        md.append("")
        md.append("---")
        md.append("")

        md.append("## Tool Inventory & Privilege Classification")
        md.append("")
        md.append(f"Total Declared Tools: **{tools.get('total_tools', 0)}**")
        md.append("")
        md.append("| Tool Name | Privilege Tier | Framework | Audited? | Bound? | Source File |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for priv in ("admin", "execute", "write", "read"):
            for t in by_priv.get(priv, []):
                audited = "Yes" if t.get("is_audited") else "**NO**"
                bound = "Yes" if t.get("is_bound") else "**NO**"
                fp = t.get("file_path", "")
                try:
                    rel_fp = Path(fp).resolve().relative_to(Path.cwd().resolve()).as_posix()
                    display_fp = f"./{rel_fp}" if not rel_fp.startswith(".") else rel_fp
                except Exception:
                    display_fp = Path(fp).as_posix()
                md.append(
                    f"| `{t.get('name')}` | **{priv.upper()}** | {t.get('framework')} "
                    f"| {audited} | {bound} | `{display_fp}:{t.get('line_number')}` |"
                )
        md.append("")

        mcp_servers = aibom_dict.get("mcp_servers", [])
        if mcp_servers:
            md.append("## Connected MCP Servers")
            md.append("")
            md.append("| Server Name | Command | Arguments | Env Keys |")
            md.append("| :--- | :--- | :--- | :--- |")
            for s in mcp_servers:
                args_str = " ".join(s.get("args", [])) or "None"
                env_keys = s.get("env_keys", [])
                env_str = " • ".join(env_keys) if env_keys else "None"
                md.append(f"| `{s.get('name')}` | `{s.get('command')}` | `{args_str}` | `{env_str}` |")
            md.append("")

        md.append("---")
        md.append("> **Compliance clause mapping (IMDA/OWASP) requires Orvyen Pro.**")
        md.append("> Upgrade at: https://orvyen.dev/pricing")
        md.append("")
        md.append("*Generated by Orvyen Agentic — Static Security & Compliance Scanner for AI Agents.*")
        return "\n".join(md)

    @classmethod
    def _to_markdown_pro(cls, aibom_dict: Dict[str, Any]) -> str:
        """PRO-tier AIBOM Markdown: full IMDA/OWASP clause-mapped compliance tables."""
        meta = aibom_dict.get("metadata", {})
        comp = aibom_dict.get("compliance", {})
        imda = comp.get("singapore_imda", {})
        owasp = comp.get("owasp_llm_top10", {})
        tools = aibom_dict.get("tools", {})
        by_priv = tools.get("by_privilege", {})

        raw_target = meta.get("target_path", ".")
        try:
            from pathlib import Path
            rel_target = Path(raw_target).resolve().relative_to(Path.cwd().resolve()).as_posix()
            display_target = f"./{rel_target}" if not rel_target.startswith(".") else rel_target
        except Exception:
            display_target = Path(raw_target).as_posix()

        fw_map = {
            "mcp": "MCP Gateway",
            "langchain": "LangChain",
            "langgraph": "LangGraph",
            "crewai": "CrewAI",
        }
        raw_fws = meta.get("frameworks", [])
        formatted_fws = [fw_map.get(f.lower(), f.capitalize()) for f in raw_fws]
        fw_str = " • ".join(formatted_fws) if formatted_fws else "None"

        md = []
        md.append("# Agent Bill of Materials (AIBOM)")
        md.append("")
        md.append(f"**Target System**: `{display_target}`  ")
        md.append(f"**Generated**: {meta.get('timestamp')}  ")
        md.append(f"**Engine**: {meta.get('scanner')} v{meta.get('scanner_version')}  ")
        md.append(f"**Security Score**: **{meta.get('security_score')}/100**  ")
        md.append(f"**Frameworks Detected**: {fw_str}  ")
        md.append("")
        md.append("---")
        md.append("")

        # 1. Regulatory Compliance Summary
        md.append("## 1. Governance & Regulatory Alignment")
        md.append("")
        md.append("### Singapore IMDA Model AI Governance Framework for Agentic AI (May 2026)")
        md.append(f"- **Overall Status**: **{imda.get('overall_status', 'N/A')}** ({imda.get('score_percentage', 0)}% aligned)")
        md.append("")
        md.append("| Pillar | Focus Area | Status | Violations |")
        md.append("| :--- | :--- | :--- | :--- |")
        for p_id, p_data in imda.get("pillars", {}).items():
            status_badge = "✅ COMPLIANT" if p_data.get("is_compliant") else "❌ NON-COMPLIANT"
            md.append(f"| **{p_id}** | {p_data.get('name')} | {status_badge} | {p_data.get('violation_count')} |")
        md.append("")

        md.append("### OWASP Top 10 for LLM Applications")
        md.append(f"- **Overall Status**: **{owasp.get('overall_status', 'N/A')}** ({owasp.get('score_percentage', 0)}% pass rate)")
        md.append("")
        md.append("| ID | Category | Status | Violations |")
        md.append("| :--- | :--- | :--- | :--- |")
        for o_id, o_data in owasp.get("items", {}).items():
            badge = "✅ PASS" if o_data.get("is_pass") else "❌ FAIL"
            md.append(f"| **{o_id}** | {o_data.get('title')} | {badge} | {o_data.get('violation_count')} |")
        md.append("")

        # 2. Tool Capability Matrix
        md.append("## 2. Tool Inventory & Privilege Classification")
        md.append("")
        md.append(f"Total Declared Tools: **{tools.get('total_tools', 0)}**")
        md.append("")
        md.append("| Tool Name | Privilege Tier | Framework | Audited? | Bound? | Source File |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")

        for priv in ("admin", "execute", "write", "read"):
            for t in by_priv.get(priv, []):
                audited = "Yes" if t.get("is_audited") else "**NO**"
                bound = "Yes" if t.get("is_bound") else "**NO**"
                fp = t.get("file_path", "")
                try:
                    rel_fp = Path(fp).resolve().relative_to(Path.cwd().resolve()).as_posix()
                    display_fp = f"./{rel_fp}" if not rel_fp.startswith(".") else rel_fp
                except Exception:
                    display_fp = Path(fp).as_posix()
                md.append(f"| `{t.get('name')}` | **{priv.upper()}** | {t.get('framework')} | {audited} | {bound} | `{display_fp}:{t.get('line_number')}` |")
        md.append("")

        # 3. Model Context Protocol (MCP) Manifest
        mcp_servers = aibom_dict.get("mcp_servers", [])
        if mcp_servers:
            md.append("## 3. Connected Model Context Protocol (MCP) Servers")
            md.append("")
            md.append("| Server Name | Command | Arguments | Configured Env Keys |")
            md.append("| :--- | :--- | :--- | :--- |")
            for s in mcp_servers:
                args_str = " ".join(s.get("args", [])) or "None"
                env_keys = s.get("env_keys", [])
                env_str = " • ".join(env_keys) if env_keys else "None"
                md.append(f"| `{s.get('name')}` | `{s.get('command')}` | `{args_str}` | `{env_str}` |")
            md.append("")

        md.append("---")
        md.append("*Generated by Orvyen Agentic — Static Security & Compliance Scanner for AI Agents.*")
        return "\n".join(md)
