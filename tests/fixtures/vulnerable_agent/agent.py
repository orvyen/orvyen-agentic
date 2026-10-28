"""
Sample vulnerable agent implementation for testing Orvyen Agentic.
"""

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END
from crewai import Agent, Crew

from tools import (
    execute_system_command,
    wipe_database,
    update_user_balance,
    exfiltrate_customer_data,
    fetch_market_data,
    run_risk_model,
    send_trade_order,
    notify_compliance,
    archive_audit_log,
)


def run_vulnerable_prompt(user_untrusted_input: str, customer_email: str, user_ssn: str):
    # OAG-002: Prompt injection via raw f-string interpolation into SystemMessage
    system_msg = SystemMessage(
        content=f"You are an automated support agent. Priority instructions: {user_untrusted_input}"
    )

    # OAG-004: Sensitive customer PII passed into external dispatch sink without masking
    external_sync_service(customer_email, user_ssn)


def external_sync_service(email: str, ssn: str):
    return f"Dispatched {email} - {ssn}"


# OAG-005: LangGraph workflow with cycle missing recursion_limit
class AgentState(dict):
    pass

workflow = StateGraph(AgentState)
workflow.add_node("agent", lambda state: {"msg": "thinking"})
workflow.add_node("tools", lambda state: {"msg": "executing"})

workflow.add_edge("agent", "tools")
workflow.add_edge("tools", "agent")  # Cycle: agent -> tools -> agent
workflow.set_entry_point("agent")

# OAG-005: Missing recursion_limit
vulnerable_app = workflow.compile()


# OAG-007: CrewAI agent configured without max_iter
# OAG-011: 9 tools bound — exceeds chain depth limit of 5
# OAG-010: Tools with EXECUTE/ADMIN privilege have no human_input=True gate
unbounded_crew_agent = Agent(
    role="Financial Planner",
    goal="Optimize trades continuously without limits",
    backstory="Autonomous trading bot with broad agency",
    tools=[
        execute_system_command,
        wipe_database,
        update_user_balance,
        exfiltrate_customer_data,
        fetch_market_data,
        run_risk_model,
        send_trade_order,
        notify_compliance,
        archive_audit_log,
    ],
    # max_iter omitted! (OAG-007)
    # human_input=True omitted! (OAG-010)
)

