"""
Scan engine coordinator: ingests codebase, runs AST & manifest parsers, and evaluates rules.
"""

from __future__ import annotations
import time
from pathlib import Path
from typing import List, Set, Optional

from orvyen.core.models import ScanResult, ToolDefinition, AgentNode, MCPServer, GraphEdge
from orvyen.core.graph import AgentWorkflowGraph
from orvyen.parsers.python_ast import parse_python_agent_file
from orvyen.parsers.mcp_parser import parse_mcp_file
from orvyen.parsers.config_parser import ConfigFileScanner
from orvyen.rules.base import ScanContext, RuleRegistry


IGNORED_DIRS: Set[str] = {
    ".git",
    ".github",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "eggs",
    ".eggs",
    "site-packages",
}


class ScanEngine:
    """Orchestrates multi-phase static scanning of agent codebases."""

    def __init__(self, target_path: Path):
        self.target_path = target_path.resolve()

    def run(self) -> ScanResult:
        start_time = time.perf_counter()

        ctx = ScanContext(target_path=self.target_path)
        all_files = self._collect_files()
        ctx.all_files = all_files

        # 1. Parse files
        for file_path in all_files:
            rel_name = file_path.name.lower()

            # Python files
            if rel_name.endswith(".py"):
                visitor = parse_python_agent_file(file_path)
                ctx.python_visitors[str(file_path)] = visitor
                ctx.tools.extend(visitor.tools)
                ctx.agents.extend(visitor.agents)
                ctx.edges.extend(visitor.edges)

                for agent in visitor.agents:
                    ctx.graph.add_node(agent)
                for edge in visitor.edges:
                    ctx.graph.add_edge(edge)

            # MCP files
            elif rel_name.endswith(".json") and ("mcp" in rel_name or "claude_desktop" in rel_name):
                mcp_parser = parse_mcp_file(file_path)
                if mcp_parser:
                    ctx.mcp_servers.extend(mcp_parser.servers)
                    ctx.tools.extend(mcp_parser.tools)

            # Config & Secret scanning (.env, yaml, json)
            if (
                rel_name.startswith(".env")
                or rel_name.endswith((".yaml", ".yml"))
                or (rel_name.endswith(".json") and not rel_name.endswith("package-lock.json"))
            ):
                cfg_scanner = ConfigFileScanner(file_path)
                findings = cfg_scanner.scan()
                ctx.config_findings.extend(findings)

        # 2. Evaluate all rules
        rules = RuleRegistry.get_all_rules()
        all_findings = []
        for rule in rules:
            try:
                rule_findings = rule.evaluate(ctx)
                all_findings.extend(rule_findings)
            except Exception as e:
                # Fault tolerant rule execution
                pass

        # Sort findings by severity level descending
        all_findings.sort(key=lambda f: f.severity.level, reverse=True)

        duration_ms = (time.perf_counter() - start_time) * 1000

        result = ScanResult(
            target_path=str(self.target_path),
            files_scanned=len(all_files),
            duration_ms=duration_ms,
            findings=all_findings,
            tools=ctx.tools,
            agents=ctx.agents,
            mcp_servers=ctx.mcp_servers,
            edges=ctx.edges,
        )

        return result

    def _collect_files(self) -> List[Path]:
        """Recursively collect scan targets while respecting ignore lists."""
        collected: List[Path] = []

        if self.target_path.is_file():
            return [self.target_path]

        for p in self.target_path.rglob("*"):
            if p.is_file():
                # Check if any parent part is in ignored dirs
                parts = p.parts
                if not any(ign in parts for ign in IGNORED_DIRS):
                    ext = p.suffix.lower()
                    name = p.name.lower()
                    if (
                        ext in (".py", ".json", ".yaml", ".yml", ".env")
                        or name.startswith(".env")
                    ):
                        collected.append(p)

        return collected
