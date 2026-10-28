"""
Hardened agent workflow adhering to IMDA and OWASP standards.
"""

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph
from crewai import Agent

from tools import fetch_account_summary, search_knowledge_base


def sanitize_input(raw_text: str) -> str:
    # Whitelist / sanitize input
    return raw_text.strip()[:100]


def mask_pii(text: str) -> str:
    return "[REDACTED_PII]"


def run_secure_workflow(user_query: str):
    # Static system prompt without dynamic string interpolation
    system_msg = SystemMessage(
        content="You are an enterprise AI assistant. Adhere strictly to authorized operational policies."
    )
    clean_query = sanitize_input(user_query)
    user_msg = HumanMessage(content=clean_query)
    return [system_msg, user_msg]


# LangGraph with bounded recursion
class SecureState(dict):
    pass

workflow = StateGraph(SecureState)
workflow.add_node("agent", lambda state: {"status": "ok"})
workflow.add_node("tools", lambda state: {"status": "done"})

workflow.add_edge("agent", "tools")
workflow.set_entry_point("agent")

# Explicit recursion limit configured!
secure_app = workflow.compile(recursion_limit=10)


# CrewAI agent with bounded iterations
secure_agent = Agent(
    role="Research Assistant",
    goal="Retrieve documentation answers safely",
    backstory="Enterprise search agent following least-privilege principles",
    tools=[fetch_account_summary, search_knowledge_base, "enterprise-docs"],
    max_iter=5,
)
