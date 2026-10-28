"""
Rule OAG-002: Prompt Injection Surface in System Instructions.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG002PromptInjection(BaseRule):
    metadata = RuleMetadata(
        id="OAG-002",
        title="Prompt Injection Surface in System Instructions",
        description=(
            "Detects raw string formatting, f-strings, or string concatenation interpolating dynamic "
            "variables directly into agent system prompts, allowing prompt injection and goal hijacking."
        ),
        severity=Severity.HIGH,
        owasp_id="LLM01:2025",
        owasp_title="Prompt Injection",
        imda_pillar="Pillar 1: Assess & Bound Risk Upfront",
        remediation=(
            "Separate system instructions from dynamic inputs. Use parameterized prompt templates, "
            "isolate untrusted content within separate User/Tool messages, or pass data as structured payloads."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        for file_path, visitor in ctx.python_visitors.items():
            for item in visitor.system_prompt_injections:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=file_path,
                        line_number=item.get("line_number", 1),
                        column=item.get("col_offset", 0) + 1,
                        code_snippet=item.get("snippet", ""),
                        message=item.get("message", "Prompt injection surface identified in system prompt."),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings
