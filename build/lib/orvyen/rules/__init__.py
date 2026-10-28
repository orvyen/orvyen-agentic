"""Rules module for Orvyen Agentic security pack."""

from orvyen.rules.base import RuleRegistry, BaseRule

# Import all rules to trigger automatic registration
from orvyen.rules.oag001_overpermission import OAG001ToolOverpermission
from orvyen.rules.oag002_prompt_injection import OAG002PromptInjection
from orvyen.rules.oag003_hardcoded_secrets import OAG003HardcodedSecrets
from orvyen.rules.oag004_pii_flow import OAG004PIIFlow
from orvyen.rules.oag005_unbounded_recursion import OAG005UnboundedRecursion
from orvyen.rules.oag006_orphaned_tools import OAG006OrphanedTools
from orvyen.rules.oag007_missing_limits import OAG007MissingLimits
from orvyen.rules.oag008_unaudited_mutations import OAG008UnauditedMutations
from orvyen.rules.oag009_insecure_mcp_transport import OAG009InsecureMCPTransport
from orvyen.rules.oag010_missing_human_in_loop import OAG010MissingHumanInLoop
from orvyen.rules.oag011_excessive_tool_chaining import OAG011ExcessiveToolChaining
from orvyen.rules.oag012_sensitive_data_exfiltration import OAG012SensitiveDataExfiltration

__all__ = [
    "RuleRegistry",
    "BaseRule",
    "OAG001ToolOverpermission",
    "OAG002PromptInjection",
    "OAG003HardcodedSecrets",
    "OAG004PIIFlow",
    "OAG005UnboundedRecursion",
    "OAG006OrphanedTools",
    "OAG007MissingLimits",
    "OAG008UnauditedMutations",
    "OAG009InsecureMCPTransport",
    "OAG010MissingHumanInLoop",
    "OAG011ExcessiveToolChaining",
    "OAG012SensitiveDataExfiltration",
]
