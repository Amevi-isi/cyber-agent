"""
Centralized rules for the agent.
This module separates the 'Rules' pillar from the 'Role' (system prompt).
"""

AGENT_RULES = [
    "Never skip the planning step.",
    "If a tool fails, try an alternative approach. Do not repeat the exact same tool call.",
    "If stuck after 3 attempts on the same step, explain why and stop.",
    "Always rely on the tools to gather information; do not hallucinate facts."
]

def get_rules_text() -> str:
    """Formats the rules as a bulleted string for injection into the system prompt."""
    formatted_rules = "\n".join(f"- {rule}" for rule in AGENT_RULES)
    return formatted_rules
