"""
Rule OAG-008: Unaudited State-Modifying Tool Actions.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity, ToolPrivilege
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG008UnauditedMutations(BaseRule):
    metadata = RuleMetadata(
        id="OAG-008",
        title="Unaudited State-Modifying Tool Actions",
        description=(
            "Flags tools performing external state mutations (database updates, filesystem writes, "
            "or network API requests) without structured audit logging, execution tracing, or callback telemetry."
        ),
        severity=Severity.HIGH,
        owasp_id="LLM06:2025",
        owasp_title="Excessive Agency",
        imda_pillar="Pillar 2: Make Humans Meaningfully Accountable",
        remediation=(
            "Attach structured audit loggers or framework callbacks (e.g. LangChain CallbackHandler, OpenTelemetry) "
            "to record tool invocation timestamp, actor identity, input arguments, and action rationale."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        for tool in ctx.tools:
            # If the tool performs state changes (WRITE, EXECUTE, ADMIN) but lacks audit logging
            if tool.privilege in (ToolPrivilege.WRITE, ToolPrivilege.EXECUTE, ToolPrivilege.ADMIN):
                if not tool.is_audited:
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
                                f"Mutating tool '{tool.name}' ({tool.privilege.value}) executes state changes "
                                f"without mandatory audit logging or execution callbacks."
                            ),
                            remediation=self.metadata.remediation,
                            owasp_id=self.metadata.owasp_id,
                            imda_pillar=self.metadata.imda_pillar,
                        )
                    )

        return findings
