"""
Graph topology analyzer for agent workflows (LangGraph, CrewAI, multi-agent chains).
"""

from __future__ import annotations
from typing import List, Dict, Set, Tuple, Optional
from orvyen.core.models import GraphEdge, AgentNode


class AgentWorkflowGraph:
    """Represents the operational graph of an agentic workflow."""

    def __init__(self):
        self.nodes: Dict[str, AgentNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, List[str]] = {}

    def add_node(self, node: AgentNode) -> None:
        self.nodes[node.name] = node
        if node.name not in self.adjacency:
            self.adjacency[node.name] = []

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        if edge.source not in self.adjacency:
            self.adjacency[edge.source] = []
        self.adjacency[edge.source].append(edge.target)
        if edge.target not in self.adjacency:
            self.adjacency[edge.target] = []

    def find_cycles(self) -> List[List[str]]:
        """
        Detect directed cycles in the agent graph using DFS with recursion stack tracking.
        Returns a list of cycles, where each cycle is a list of node names.
        """
        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        cycles: List[List[str]] = []
        current_path: List[str] = []

        def dfs(node: str) -> None:
            visited.add(node)
            rec_stack.add(node)
            current_path.append(node)

            for neighbor in self.adjacency.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # Found cycle!
                    cycle_start_idx = current_path.index(neighbor)
                    cycle = list(current_path[cycle_start_idx:]) + [neighbor]
                    cycles.append(cycle)

            current_path.pop()
            rec_stack.remove(node)

        for node in list(self.adjacency.keys()):
            if node not in visited:
                dfs(node)

        return cycles

    def has_unbounded_cycle(self, default_limit: Optional[int] = None) -> Tuple[bool, List[List[str]]]:
        """
        Check if any cycle exists without a configured recursion limit.
        """
        cycles = self.find_cycles()
        if not cycles:
            return False, []

        unbounded_cycles = []
        for cycle in cycles:
            # Check if any node in the cycle has a recursion_limit configured
            has_limit = any(
                self.nodes.get(node_name) and self.nodes[node_name].recursion_limit is not None
                for node_name in cycle
            )
            if not has_limit and default_limit is None:
                unbounded_cycles.append(cycle)

        return len(unbounded_cycles) > 0, unbounded_cycles
