"""
Origin trust model.

Until this existed, `Finding.origin` was tracked faithfully and then
ignored: neither the risk engine nor the policy engine ever read it. That
made "provenance-aware" a false claim -- an instruction-override finding
in a user's own message and the identical finding inside a retrieved
document produced exactly the same score and the same decision.

That equivalence is wrong, and it's wrong in a specific, defensible
direction: a user typing "ignore previous instructions" is a person
talking to their own assistant, which is at worst a nuisance. The same
sentence arriving inside a retrieved document, a tool response, or an
MCP tool description is an *external party* injecting instructions into
a conversation they are not a participant in. Same text, different
provenance, genuinely different threat.

The multipliers below are a deliberate, stated modeling choice, NOT a
calibrated or empirically-derived result. They encode an ordering
(user input < RAG context < tool/MCP output) that follows directly from
the trust model, and the ordering is the claim -- the specific constants
are not. Anyone re-deriving these from real data should expect different
numbers, and the code is structured so a single table changes them.

Reference for the trust ordering: the standard indirect-prompt-injection
threat model, in which attacker-controlled external content reaching the
model's context is the core danger (Greshake et al., 2023), and the
long-standing security principle that data crossing a trust boundary is
untrusted until proven otherwise.
"""

# Multiplier applied to a finding's severity weight, by origin prefix.
# Longest-prefix wins, so "tool_arguments:shell.execute" resolves via
# "tool_arguments" without needing an entry per tool name.
ORIGIN_TRUST_MULTIPLIERS: dict[str, float] = {
    # The user talking to their own assistant. Baseline -- not elevated.
    "input": 1.0,
    # The model's own output. Elevated: an injection surfacing here means
    # something upstream already succeeded.
    "output": 1.2,
    # Retrieved documents. Attacker-controlled in the classic indirect
    # prompt injection threat model; the user never wrote this text.
    "context": 1.5,
    # Tool responses. Same untrusted-external-content argument as RAG, and
    # tool output is frequently fed straight back into the model.
    "tool_response": 1.5,
    # Arguments the MODEL generated for a privileged action. Highest,
    # because this is the point where text becomes a real-world effect.
    "tool_arguments": 1.8,
    # MCP tool descriptions. Highest alongside tool arguments: a poisoned
    # description is read by the model as instructions before any tool is
    # ever called, and it persists across every session using that server.
    "tool_description": 1.8,
}

DEFAULT_MULTIPLIER = 1.0


def trust_multiplier(origin: str) -> float:
    """
    Resolves an origin string to its trust multiplier.

    Origins carry suffixes ("context:2", "tool_arguments:shell.execute"),
    so this matches on the prefix before the first colon and falls back to
    the neutral default for anything unrecognized -- an unknown origin must
    never silently inflate or deflate a score.
    """
    prefix = origin.split(":", 1)[0]
    return ORIGIN_TRUST_MULTIPLIERS.get(prefix, DEFAULT_MULTIPLIER)
