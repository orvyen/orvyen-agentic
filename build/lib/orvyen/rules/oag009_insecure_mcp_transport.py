"""
Rule OAG-009: Insecure MCP Transport.

Detects MCP server configurations using plaintext HTTP (without TLS) or
Server-Sent Events (SSE) endpoints without authentication headers.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG009InsecureMCPTransport(BaseRule):
    metadata = RuleMetadata(
        id="OAG-009",
        title="Insecure MCP Transport (HTTP without TLS / SSE without Auth)",
        description=(
            "Detects MCP server connections configured over plaintext HTTP or SSE endpoints "
            "without authentication tokens, exposing tool invocations and agent state to "
            "network-level interception and man-in-the-middle attacks."
        ),
        severity=Severity.HIGH,
        owasp_id="LLM09:2025",
        owasp_title="Misinformation",
        imda_pillar="Pillar 3: Implement Technical Controls",
        remediation=(
            "Replace all MCP transport URIs with HTTPS/WSS endpoints. For SSE-based transports, "
            "require bearer token authentication via Authorization headers or mTLS certificates."
        ),
    )

    # Insecure transport patterns in command / args strings
    _HTTP_PATTERNS = ("http://", "http://localhost", "http://127.")
    _SSE_PATTERNS = ("/sse", "/events", "text/event-stream")

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        for server in ctx.mcp_servers:
            combined = " ".join([server.command] + server.args).lower()

            # 1. Plaintext HTTP transport
            if any(p in combined for p in self._HTTP_PATTERNS):
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=Severity.HIGH,
                        file_path=server.file_path,
                        line_number=server.line_number,
                        column=1,
                        code_snippet=(
                            f'"{server.name}": {{"command": "{server.command}", '
                            f'"args": {server.args}}}'
                        ),
                        message=(
                            f"MCP Server '{server.name}' configured with plaintext HTTP transport. "
                            "All tool calls are transmitted without encryption."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

            # 2. SSE transport without authentication
            elif any(p in combined for p in self._SSE_PATTERNS):
                has_auth = any(
                    k.lower() in ("authorization", "x-api-key", "x-auth-token")
                    for k in server.env_vars
                )
                if not has_auth:
                    findings.append(
                        Finding(
                            rule_id=self.metadata.id,
                            rule_title=self.metadata.title,
                            severity=Severity.HIGH,
                            file_path=server.file_path,
                            line_number=server.line_number,
                            column=1,
                            code_snippet=(
                                f'"{server.name}": {{"command": "{server.command}", '
                                f'"args": {server.args}}}'
                            ),
                            message=(
                                f"MCP Server '{server.name}' uses SSE transport without "
                                "an Authorization/API-key header configured in env."
                            ),
                            remediation=self.metadata.remediation,
                            owasp_id=self.metadata.owasp_id,
                            imda_pillar=self.metadata.imda_pillar,
                        )
                    )

        return findings
