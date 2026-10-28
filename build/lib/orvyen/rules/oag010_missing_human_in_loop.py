"""
Rule OAG-010: Missing Human-in-the-Loop for High-Privilege Operations.

Flags agent tools with ADMIN or EXECUTE privilege that lack any human
approval gate before being invoked. High-privilege actions must be
gated behind an interrupt, confirmation callback, or approval workflow.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity, ToolPrivilege
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG010MissingHumanInLoop(BaseRule):
    metadata = RuleMetadata(
        id="OAG-010",
        title="Missing Human-in-the-Loop for ADMIN/EXECUTE Privilege Tools",
        description=(
            "Identifies tools with ADMIN or EXECUTE privilege tier that are not gated behind "
            "any human approval check, confirmation callback, or interrupt mechanism. "
            "Per IMDA Pillar 2 and OWASP LLM06, high-impact actions require explicit human "
            "oversight before execution."
        ),
        severity=Severity.HIGH,
        owasp_id="LLM06:2025",
        owasp_title="Excessive Agency",
        imda_pillar="Pillar 2: Make Humans Meaningfully Accountable",
        remediation=(
            "Wrap ADMIN/EXECUTE tools with a human approval gate using LangGraph interrupt(), "
            "CrewAI human_input=True, or an explicit confirmation callback before executing "
            "irreversible operations."
        ),
    )

    # Token patterns that indicate a human approval mechanism is present
    _APPROVAL_TOKENS = (
        "interrupt", "human_input", "approval", "confirm", "authorize",
        "hitl", "human_in_the_loop", "review", "checkpoint",
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # Build a set of all source lines that reference an approval token
        approval_lines: set = set()
        for visitor in ctx.python_visitors.values():
            for lineno, line in enumerate(visitor.lines, start=1):
                line_lower = line.lower()
                if any(tok in line_lower for tok in self._APPROVAL_TOKENS):
                    approval_lines.add((visitor.file_path, lineno))

        for tool in ctx.tools:
            if tool.privilege not in (ToolPrivilege.EXECUTE, ToolPrivilege.ADMIN):
                continue

            # Check if any approval token appears near this tool in the same file
            # (within ±20 lines of the definition) or anywhere in the file
            has_approval = False
            visitor = ctx.python_visitors.get(tool.file_path)
            if visitor:
                for (fpath, lno) in approval_lines:
                    if fpath == tool.file_path:
                        has_approval = True
                        break

            if not has_approval:
                sev = (
                    Severity.CRITICAL
                    if tool.privilege == ToolPrivilege.ADMIN
                    else Severity.HIGH
                )
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
                            f"Tool '{tool.name}' has {tool.privilege.value} privilege "
                            "but no human approval gate (interrupt/confirm/human_input) "
                            "was detected in the file."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings
