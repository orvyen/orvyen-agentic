"""
Rule OAG-006: Orphaned & Undocumented Tools and MCP Servers.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG006OrphanedTools(BaseRule):
    metadata = RuleMetadata(
        id="OAG-006",
        title="Orphaned & Undocumented Tools or MCP Servers",
        description=(
            "Identifies tools declared, imported, or configured in MCP server manifests that are "
            "never bound to an agent executor, graph node, or task, leaving an unreviewed attack surface."
        ),
        severity=Severity.MEDIUM,
        owasp_id="LLM06:2025",
        owasp_title="Excessive Agency",
        imda_pillar="Pillar 2: Make Humans Meaningfully Accountable",
        remediation=(
            "Prune dormant tools from agent configuration manifests and remove unused tool code to maintain "
            "a minimal, reviewed operational attack surface."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # Gather all bound tool names across all agents & AST visitors
        bound_tool_names = set()
        for visitor in ctx.python_visitors.values():
            bound_tool_names.update(visitor.bound_tool_names)
        for agent in ctx.agents:
            bound_tool_names.update(agent.bound_tools)

        # 1. Check Python tools
        for tool in ctx.tools:
            if tool.framework == "mcp":
                continue
            is_bound = (
                tool.name in bound_tool_names
                or tool.name.replace("mcp::", "") in bound_tool_names
            )
            # If tool is never referenced in bound tools and there are active agents defined
            if ctx.agents and not is_bound:
                tool.is_bound = False
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=tool.file_path,
                        line_number=tool.line_number,
                        column=1,
                        code_snippet=tool.raw_code or f"def {tool.name}(...)",
                        message=(
                            f"Tool '{tool.name}' is declared/imported but never bound to any agent or workflow."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )
            else:
                tool.is_bound = True

        # 2. Check MCP servers if agents exist but no agent references MCP tools
        for server in ctx.mcp_servers:
            # Check if any agent references this server
            mcp_tool_name = f"mcp::{server.name}"
            if ctx.agents and mcp_tool_name not in bound_tool_names and server.name not in bound_tool_names:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=Severity.LOW,
                        file_path=server.file_path,
                        line_number=server.line_number,
                        column=1,
                        code_snippet=f'"{server.name}": {{ "command": "{server.command}" }}',
                        message=(
                            f"MCP Server '{server.name}' is registered in manifest but not referenced by agent code."
                        ),
                        remediation="Remove obsolete MCP servers from config manifests.",
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings
