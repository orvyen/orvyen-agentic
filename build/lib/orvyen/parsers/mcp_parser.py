"""
Parser for Model Context Protocol (MCP) configuration manifests.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from orvyen.core.models import MCPServer, ToolDefinition, ToolPrivilege


class MCPManifestParser:
    """Parses MCP configurations (claude_desktop_config.json, mcp.json)."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.servers: List[MCPServer] = []
        self.tools: List[ToolDefinition] = []
        self.raw_data: Dict[str, Any] = {}

    def parse(self) -> None:
        try:
            content = self.file_path.read_text(encoding="utf-8", errors="replace")
            self.raw_data = json.loads(content)
        except Exception:
            return

        # Check standard MCP keys: "mcpServers" or direct server dictionary
        servers_dict = self.raw_data.get("mcpServers", {})
        if not servers_dict and isinstance(self.raw_data, dict):
            # Check if root contains server-like objects
            for k, v in self.raw_data.items():
                if isinstance(v, dict) and "command" in v:
                    servers_dict[k] = v

        for server_name, server_cfg in servers_dict.items():
            if not isinstance(server_cfg, dict):
                continue

            command = str(server_cfg.get("command", ""))
            args = [str(a) for a in server_cfg.get("args", [])]
            env_vars = {str(k): str(v) for k, v in server_cfg.get("env", {}).items()}
            declared_tools = [str(t) for t in server_cfg.get("tools", [])]

            server = MCPServer(
                name=server_name,
                command=command,
                args=args,
                env_vars=env_vars,
                tools=declared_tools,
                file_path=str(self.file_path),
                line_number=1,
            )
            self.servers.append(server)

            # Determine privileges from command and args
            privilege = ToolPrivilege.READ
            dangerous_sinks = []
            cmd_lower = command.lower()

            if any(sh in cmd_lower for sh in ("bash", "sh", "cmd", "powershell", "zsh", "terminal")):
                privilege = ToolPrivilege.EXECUTE
                dangerous_sinks.append(f"MCPShellCommand: {command}")
            elif any(d in cmd_lower for d in ("sqlite", "postgres", "mysql")):
                privilege = ToolPrivilege.WRITE

            tool_def = ToolDefinition(
                name=f"mcp::{server_name}",
                framework="mcp",
                privilege=privilege,
                file_path=str(self.file_path),
                line_number=1,
                dangerous_sinks=dangerous_sinks,
                parameters=args,
                docstring=f"MCP Server: {command} {' '.join(args)}",
                is_audited=False,
                is_bound=False,
            )
            self.tools.append(tool_def)


def parse_mcp_file(file_path: Path) -> Optional[MCPManifestParser]:
    """Inspect and parse an MCP manifest file."""
    name_lower = file_path.name.lower()
    if name_lower.endswith(".json") and (
        "mcp" in name_lower or "claude_desktop_config" in name_lower
    ):
        parser = MCPManifestParser(file_path)
        parser.parse()
        return parser
    return None
