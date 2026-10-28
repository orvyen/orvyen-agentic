"""
Rule OAG-001: Tool Over-Permissioning and Dangerous Execution Scope.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity, ToolPrivilege
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG001ToolOverpermission(BaseRule):
    metadata = RuleMetadata(
        id="OAG-001",
        title="Tool Over-Permissioning & Dangerous Execution Scope",
        description=(
            "Identifies agent tools granted dangerous system access (arbitrary shell execution, "
            "unbounded filesystem deletion, or unrestricted database modification) without sandboxing."
        ),
        severity=Severity.HIGH,
        owasp_id="LLM06:2025",
        owasp_title="Excessive Agency",
        imda_pillar="Pillar 3: Implement Technical Controls",
        remediation=(
            "Constrain tool privileges to the exact minimum necessary. Replace raw shell or database "
            "execution tools with parameterized, read-only or strictly whitelisted operational handlers."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Check Python defined tools
        for tool in ctx.tools:
            if tool.privilege in (ToolPrivilege.EXECUTE, ToolPrivilege.ADMIN):
                sev = Severity.CRITICAL if tool.privilege == ToolPrivilege.EXECUTE else Severity.HIGH
                sinks_str = ", ".join(tool.dangerous_sinks) if tool.dangerous_sinks else "High privilege operations"
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=sev,
                        file_path=tool.file_path,
                        line_number=tool.line_number,
                        column=1,
                        code_snippet=tool.raw_code or f"def {tool.name}(...)",
                        message=(
                            f"Tool '{tool.name}' possesses excessive privilege ({tool.privilege.value}). "
                            f"Detected capabilities: {sinks_str}."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        # 2. Check MCP Server tools with raw shell commands
        for server in ctx.mcp_servers:
            cmd_lower = server.command.lower()
            if any(sh in cmd_lower for sh in ("bash", "sh", "cmd", "powershell", "zsh")):
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=Severity.CRITICAL,
                        file_path=server.file_path,
                        line_number=server.line_number,
                        column=1,
                        code_snippet=f'"{server.name}": {{ "command": "{server.command}", "args": {server.args} }}',
                        message=(
                            f"MCP Server '{server.name}' grants unbounded shell interpreter access ('{server.command}')."
                        ),
                        remediation="Remove raw shell MCP servers or replace with narrowly scoped command microservices.",
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings
