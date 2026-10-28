"""
Rule OAG-011: Excessive Tool Chaining.

Detects agent graphs or workflows where a single agent invocation can
traverse a tool chain of depth >5, creating unconstrained blast radius
and allowing adversarial prompt injection to propagate across multiple
tool contexts.
"""

from typing import List, Dict, Set
from orvyen.core.models import Finding, RuleMetadata, Severity
from orvyen.rules.base import BaseRule, RuleRegistry, ScanContext

_CHAIN_DEPTH_LIMIT = 5


@RuleRegistry.register
class OAG011ExcessiveToolChaining(BaseRule):
    metadata = RuleMetadata(
        id="OAG-011",
        title="Excessive Tool Chaining (Chain Depth >5)",
        description=(
            "Identifies agent configurations that allow sequential tool invocations exceeding "
            "5 hops in a single reasoning cycle. Deep tool chains amplify prompt injection blast "
            "radius and make audit trails intractable. Each hop multiplies the agent's potential "
            "side-effect surface."
        ),
        severity=Severity.MEDIUM,
        owasp_id="LLM06:2025",
        owasp_title="Excessive Agency",
        imda_pillar="Pillar 1: Assess and Bound Risk Upfront",
        remediation=(
            "Limit the number of tools bound to any single agent to ≤5. For complex workflows, "
            "decompose into specialized sub-agents with narrow tool scopes and explicit "
            "handoff contracts."
        ),
    )

    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        for agent in ctx.agents:
            tool_count = len(agent.bound_tools)
            if tool_count > _CHAIN_DEPTH_LIMIT:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=agent.file_path,
                        line_number=agent.line_number,
                        column=1,
                        code_snippet=f"Agent(role={agent.name!r}, tools=[{', '.join(agent.bound_tools)}])",
                        message=(
                            f"Agent '{agent.name}' is bound to {tool_count} tools, "
                            f"exceeding the maximum safe chain depth of {_CHAIN_DEPTH_LIMIT}. "
                            "Bound tools: " + ", ".join(agent.bound_tools) + "."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        # Also check graph topology: count reachable nodes (tool nodes) from entry
        # A deep linear or branching chain of graph nodes also indicates chaining risk
        if ctx.edges:
            max_depth = self._max_graph_depth(ctx)
            if max_depth > _CHAIN_DEPTH_LIMIT:
                # Use the first edge's file_path as location reference
                ref_edge = ctx.edges[0]
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_title=self.metadata.title,
                        severity=self.metadata.severity,
                        file_path=ref_edge.file_path,
                        line_number=ref_edge.line_number,
                        column=1,
                        code_snippet=f"workflow.add_edge('{ref_edge.source}', '{ref_edge.target}')",
                        message=(
                            f"Agent workflow graph has a maximum reachable depth of {max_depth} nodes, "
                            f"exceeding the safe chain limit of {_CHAIN_DEPTH_LIMIT}. "
                            "Consider splitting into bounded sub-graphs."
                        ),
                        remediation=self.metadata.remediation,
                        owasp_id=self.metadata.owasp_id,
                        imda_pillar=self.metadata.imda_pillar,
                    )
                )

        return findings

    @staticmethod
    def _max_graph_depth(ctx: ScanContext) -> int:
        """BFS to find the maximum reachable depth from any entry node."""
        adjacency: Dict[str, List[str]] = {}
        all_targets: Set[str] = set()
        all_sources: Set[str] = set()

        for edge in ctx.edges:
            adjacency.setdefault(edge.source, []).append(edge.target)
            all_targets.add(edge.target)
            all_sources.add(edge.source)

        # Entry nodes are those that appear as sources but never as targets
        entry_nodes = all_sources - all_targets
        if not entry_nodes:
            entry_nodes = all_sources  # fallback: all sources

        max_depth = 0
        for start in entry_nodes:
            visited: Set[str] = set()
            queue = [(start, 0)]
            while queue:
                node, depth = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                max_depth = max(max_depth, depth)
                for neighbor in adjacency.get(node, []):
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1))

        return max_depth
