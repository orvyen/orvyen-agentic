"""
Rule OAG-007: Missing Rate Limits & Autonomous Step Budgets.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG007MissingLimits(BaseRule):
    metadata = RuleMetadata(
        id="OAG-007",
        title="Missing Rate-Limits & Autonomous Step Budgets",
        description=(
            "Detects autonomous agent loops or multi-agent orchestrations lacking step budgets, "
            "token ceilings, or invocation rate-limiting controls, risking runaway API spend and resource exhaustion."
        ),
        severity=Severity.MEDIUM,
        owasp_id="LLM10:2025",
        owasp_title="Unbounded Consumption",
        imda_pillar="Pillar 3: Implement Technical Controls",
        remediation=(
            "Configure step caps (e.g., max_iterations=10), implement token budget governors, "
            "and attach exponential backoff or rate-limiting decorators to tool dispatchers."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        for agent in ctx.agents:
            # Check if agent has no step limit or budget
            if agent.step_limit is None and agent.recursion_limit is None:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=agent.file_path,
                        line_number=agent.line_number,
                        column=1,
                        code_snippet=f"Agent(name='{agent.name}', framework='{agent.framework}')",
                        message=(
                            f"Agent '{agent.name}' lacks an explicit execution step budget or rate-limiting constraint."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings
