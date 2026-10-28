"""
Rule OAG-003: Hardcoded Credentials & API Keys in Agent Code and Configurations.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG003HardcodedSecrets(BaseRule):
    metadata = RuleMetadata(
        id="OAG-003",
        title="Hardcoded Credentials & API Keys in Configuration",
        description=(
            "Identifies API keys, authentication tokens, or private credentials stored directly in "
            "agent source code, environment manifests, or MCP server configuration files."
        ),
        severity=Severity.CRITICAL,
        owasp_id="LLM02:2025",
        owasp_title="Sensitive Information Disclosure",
        imda_pillar="Pillar 3: Implement Technical Controls",
        remediation=(
            "Remove plain-text credentials immediately. Load all keys dynamically from environment "
            "variables or an enterprise secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Check findings from config scanner (.env, json, yaml)
        for item in ctx.config_findings:
            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_title=self.metadata.title,
                    severity=self.metadata.severity,
                    file_path=item["file_path"],
                    line_number=item["line_number"],
                    column=item.get("column", 1),
                    code_snippet=item["snippet"],
                    message=item["message"],
                    remediation=self.metadata.remediation,
                    owasp_id=self.metadata.owasp_id,
                    imda_pillar=self.metadata.imda_pillar,
                )
            )

        # 2. Check MCP server env maps for hardcoded values
        for server in ctx.mcp_servers:
            for env_key, env_val in server.env_vars.items():
                val_clean = env_val.strip()
                # Check if it looks like a hardcoded secret rather than a reference like ${ENV_VAR}
                if len(val_clean) > 8 and not val_clean.startswith("$") and any(
                    k in env_key.lower() for k in ("key", "secret", "token", "password", "auth")
                ):
                    redacted = val_clean[:3] + "*" * (max(4, len(val_clean) - 5)) + val_clean[-2:]
                    findings.append(
                        Finding(
                            rule_id=self.metadata.id,
                            rule_title=self.metadata.title,
                            severity=self.metadata.severity,
                            file_path=server.file_path,
                            line_number=server.line_number,
                            column=1,
                            code_snippet=f'"{env_key}": "{redacted}"',
                            message=f"MCP server '{server.name}' embeds plaintext credential '{env_key}'.",
                            remediation=self.metadata.remediation,
                            owasp_id=self.metadata.owasp_id,
                            imda_pillar=self.metadata.imda_pillar,
                        )
                    )

        return findings
