"""Unit tests for tool-name authorization."""

from app.models.finding import Decision
from app.services.tool_policy import authorize_tool, load_tool_policy

TEST_POLICY = {
    "default": "warn",
    "tools": {
        "database.read": "allow",
        "database.delete": "block",
        "payment.transfer": "human_approval",
    },
}


def test_known_tool_uses_explicit_rule():
    assert authorize_tool("database.read", policy=TEST_POLICY) == Decision.ALLOW
    assert authorize_tool("database.delete", policy=TEST_POLICY) == Decision.BLOCK


def test_human_approval_tool():
    assert authorize_tool("payment.transfer", policy=TEST_POLICY) == Decision.HUMAN_APPROVAL


def test_unknown_tool_uses_default():
    assert authorize_tool("some.brand.new.tool", policy=TEST_POLICY) == Decision.WARN


def test_default_policy_file_loads_and_is_well_formed():
    policy = load_tool_policy()
    assert "default" in policy
    assert "tools" in policy
    assert authorize_tool("database.delete", policy=policy) == Decision.BLOCK
    assert authorize_tool("payment.transfer", policy=policy) == Decision.HUMAN_APPROVAL
