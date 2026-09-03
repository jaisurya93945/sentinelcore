"""
Tool authorization policy.

Deterministic, outside-the-model authorization for agent tool calls, by
tool name. Kept separate from the finding-based risk/policy engine on
purpose: tool-name authorization is fundamentally a lookup, not a risk
calculation. "Is this agent allowed to call payment.transfer" doesn't
get more or less true by combining severities the way "how suspicious
is this text" does.

This is also the concrete implementation of a principle worth stating
plainly: the LLM must never be the ultimate authorization authority.
This lookup happens entirely outside and independently of anything the
model itself decided to do.
"""

from pathlib import Path

import yaml

from app.models.finding import Decision

DEFAULT_TOOL_POLICY_PATH = Path(__file__).parent / "tool_policy.yaml"


def load_tool_policy(path: Path | None = None) -> dict:
    policy_path = path or DEFAULT_TOOL_POLICY_PATH
    with open(policy_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def authorize_tool(tool_name: str, policy: dict | None = None) -> Decision:
    policy = policy if policy is not None else load_tool_policy()
    tools: dict[str, str] = policy.get("tools", {})
    default: str = policy.get("default", "warn")
    action = tools.get(tool_name, default)
    return Decision(action)
