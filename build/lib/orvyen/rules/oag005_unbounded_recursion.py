"""
Rule OAG-005: Unbounded Agent-to-Agent Recursion and Graph Cycles.
"""

from typing import List
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext


@RuleRegistry.register
class OAG005UnboundedRecursion(BaseRule):
    metadata = RuleMetadata(
        id="OAG-005",
        title="Unbounded Agent-to-Agent Recursion & Graph Cycles",
        description=(
            "Detects multi-agent workflows containing cyclic transitions, recursive delegation, or "
            "agent feedback loops lacking explicit recursion depth caps or step limits."
        ),
        severity=Severity.HIGH,
        owasp_id="LLM10:2025",
        owasp_title="Unbounded Consumption",
        imda_pillar="Pillar 1: Assess & Bound Risk Upfront",
        remediation=(
            "Enforce strict execution bounds: configure 'recursion_limit' on LangGraph compiles/invocations, "
            "set 'max_iter' on CrewAI agents, and configure maximum retry timeouts on multi-agent handoffs."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Check graph cycles detected in topology
        has_cycle, cycles = ctx.graph.has_unbounded_cycle()
        if has_cycle:
            for cycle in cycles:
                cycle_str = " -> ".join(cycle)
                first_node_name = cycle[0]
                node_obj = ctx.graph.nodes.get(first_node_name)
                file_path = node_obj.file_path if node_obj else str(ctx.target_path)
                line_no = node_obj.line_number if node_obj else 1

                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=file_path,
                        line_number=line_no,
                        column=1,
                        code_snippet=f"Cycle: {cycle_str}",
                        message=(
                            f"Cyclic agent topology detected ({cycle_str}) without an explicit recursion limit circuit breaker."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        # 2. Check unconstrained compilation / agents reported by AST visitors
        for file_path, visitor in ctx.python_visitors.items():
            for item in visitor.unbounded_loops:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=file_path,
                        line_number=item.get("line_number", 1),
                        column=item.get("col_offset", 0) + 1,
                        code_snippet=item.get("snippet", ""),
                        message=item.get("message", "Agent framework component lacks recursion bounds."),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings
