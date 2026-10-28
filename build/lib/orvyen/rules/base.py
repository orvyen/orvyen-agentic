"""
Base rule class and registry for Orvyen Agentic security rules.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Type, Any, Optional

from orvyen.core.models import (
    Finding,
    RuleMetadata,
    ToolDefinition,
    AgentNode,
    GraphEdge,
    MCPServer,
)
from orvyen.core.graph import AgentWorkflowGraph
from orvyen.parsers.python_ast import PythonAgentASTVisitor


@dataclass
class ScanContext:
    """Holds all parsed artifacts from the codebase for rule evaluation."""
    target_path: Path
    python_visitors: Dict[str, PythonAgentASTVisitor] = field(default_factory=dict)
    tools: List[ToolDefinition] = field(default_factory=list)
    agents: List[AgentNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    graph: AgentWorkflowGraph = field(default_factory=AgentWorkflowGraph)
    mcp_servers: List[MCPServer] = field(default_factory=list)
    config_findings: List[Dict[str, Any]] = field(default_factory=list)
    all_files: List[Path] = field(default_factory=list)


class BaseRule(ABC):
    """Abstract base class for static security and compliance rules."""

    metadata: RuleMetadata

    @abstractmethod
    def evaluate(self, ctx: ScanContext) -> List[Finding]:
        """Inspect the parsed context and return security findings."""
        pass


class RuleRegistry:
    """Registry of all available security and compliance rules."""

    _rules: Dict[str, Type[BaseRule]] = {}

    @classmethod
    def register(cls, rule_cls: Type[BaseRule]) -> Type[BaseRule]:
        cls._rules[rule_cls.metadata.id] = rule_cls
        return rule_cls

    @classmethod
    def get_all_rules(cls) -> List[BaseRule]:
        return [rule_cls() for rule_cls in cls._rules.values()]

    @classmethod
    def get_rule(cls, rule_id: str) -> Optional[BaseRule]:
        rule_cls = cls._rules.get(rule_id)
        return rule_cls() if rule_cls else None
