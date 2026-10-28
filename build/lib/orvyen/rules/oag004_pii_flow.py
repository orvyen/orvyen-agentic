"""
Rule OAG-004: Unfiltered PII Routing to External Tools and Prompts.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG004PIIFlow(BaseRule):
    metadata = RuleMetadata(
        id="OAG-004",
        title="Unfiltered PII Routing to Tools & Prompt Sinks",
        description=(
            "Identifies customer PII (e.g. emails, phone numbers, identification numbers, credit cards) "
            "flowing into external tool calls or remote LLM completions without an intermediate redaction step."
        ),
        severity=Severity.HIGH,
        owasp_id="LLM02:2025",
        owasp_title="Sensitive Information Disclosure",
        imda_pillar="Pillar 3: Implement Technical Controls",
        remediation=(
            "Implement an automated PII anonymizer/redaction node (e.g. Microsoft Presidio, regex scrubber) "
            "prior to dispatching data to external models or third-party tool APIs."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        for file_path, visitor in ctx.python_visitors.items():
            for pii_item in visitor.pii_exposures:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=file_path,
                        line_number=pii_item.get("line_number", 1),
                        column=pii_item.get("col_offset", 0) + 1,
                        code_snippet=pii_item.get("snippet", ""),
                        message=pii_item.get("message", "Unsanitized PII dispatched to external call."),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings
