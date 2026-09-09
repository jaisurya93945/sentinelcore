"""
Public API.

Everything else in this package is internal and may change. This module is
the stable surface, and the three shapes below exist because developers
arrive with different constraints:

    Guard.scan(...)        a library call, no server, no proxy
    Guard.middleware()     ASGI middleware for an existing app
    the reverse proxy      already shipped, for zero-code-change adoption

The library and middleware paths are the ones most people can actually
adopt: they do not require re-pointing an LLM client's base_url, which
many deployments cannot do.

DESIGN NOTE -- why `scan` returns a decision rather than raising
A security library that raises by default forces every caller into
try/except and encourages blanket suppression. `scan` returns a result the
caller inspects; `guard()` raises for callers who want fail-fast. Both are
explicit, neither is the hidden default.
"""

from dataclasses import dataclass, field
from typing import Any, Callable

from sentinelcore.core.config import settings
from sentinelcore.detectors.registry import get_registered_detectors
from sentinelcore.models.finding import Decision, EnforcementStatus, Finding
from sentinelcore.services.policy_engine import decide, load_policy, most_severe
from sentinelcore.services.risk_engine import calculate_risk_score
from sentinelcore.services.sanitizer import enforce_sanitize
from sentinelcore.services.tool_policy import authorize_tool

__all__ = ["Guard", "ScanOutcome", "Decision", "EnforcementStatus", "Blocked"]


class Blocked(Exception):
    """Raised by Guard.guard() when a decision would stop the action."""

    def __init__(self, outcome: "ScanOutcome"):
        super().__init__(f"blocked by SentinelCore: {outcome.decision.value} (risk {outcome.risk_score})")
        self.outcome = outcome


@dataclass
class ScanOutcome:
    decision: Decision
    risk_score: int
    findings: list[Finding] = field(default_factory=list)
    sanitized_text: str | None = None
    enforcement_status: EnforcementStatus = EnforcementStatus.NOT_APPLICABLE

    @property
    def allowed(self) -> bool:
        """True only for ALLOW and WARN. SANITIZE, HUMAN_APPROVAL and BLOCK
        all mean 'do not proceed as-is' -- treating SANITIZE as allowed is
        the mistake this property exists to prevent, since the caller must
        use `sanitized_text` instead of the original."""
        return self.decision in (Decision.ALLOW, Decision.WARN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "enforcement_status": self.enforcement_status.value,
            "sanitized_text": self.sanitized_text,
            "findings": [f.model_dump(mode="json") for f in self.findings],
        }


# Named presets. The operating points are the ones this project actually
# measured (docs/research/README.md); a preset that was not measured would
# be a guess wearing a label.
PRESETS: dict[str, dict[str, Any]] = {
    "strict": {"detectors": None, "sanitize": True, "ml": True},
    "balanced": {"detectors": None, "sanitize": True, "ml": False},
    "permissive": {"detectors": None, "sanitize": False, "ml": False},
}


class Guard:
    """
    The entry point.

        from sentinelcore import Guard
        guard = Guard(policy="balanced")

        outcome = guard.scan("ignore all previous instructions")
        if not outcome.allowed:
            ...
    """

    def __init__(
        self,
        policy: str | dict = "balanced",
        *,
        enable_ml: bool | None = None,
        enable_semantic: bool | None = None,
    ):
        if isinstance(policy, str):
            if policy not in PRESETS:
                raise ValueError(f"unknown preset {policy!r}; expected one of {sorted(PRESETS)}")
            self._preset = PRESETS[policy]
            self._policy_name = policy
        else:
            self._preset = {**PRESETS["balanced"], **policy}
            self._policy_name = "custom"

        self._policy = load_policy()
        # Optional detectors stay opt-in. Enabling ML by preset would make
        # scikit-learn a de facto requirement of `pip install sentinelcore`.
        if enable_ml is not None:
            settings.ml_detector_enabled = enable_ml
        if enable_semantic is not None:
            settings.semantic_detector_enabled = enable_semantic

    # ---------------------------------------------------------------- core

    def scan(self, text: str, *, origin: str = "input") -> ScanOutcome:
        """Scan one piece of text. `origin` is the provenance class and it
        affects the outcome -- see docs/research/README.md; passing the
        default for retrieved content silently discards that signal."""
        findings: list[Finding] = []
        for cls in get_registered_detectors().values():
            found = cls().detect(text)
            for f in found:
                f.origin = origin
            findings.extend(found)

        score = calculate_risk_score(findings)
        decision = decide(findings, score, policy=self._policy)
        outcome = ScanOutcome(decision=decision, risk_score=score, findings=findings)

        if decision == Decision.SANITIZE and self._preset.get("sanitize", True):
            result = enforce_sanitize(text, findings)
            outcome.sanitized_text = result.sanitized_text
            outcome.enforcement_status = result.enforcement_status
            outcome.decision = result.decision
            outcome.risk_score = result.risk_score
            outcome.findings = result.findings

        return outcome

    def scan_documents(self, documents: list[str]) -> ScanOutcome:
        """Retrieved/RAG content. Tagged `context:<i>`, which the risk
        engine weights above user input."""
        findings: list[Finding] = []
        for i, doc in enumerate(documents):
            for cls in get_registered_detectors().values():
                found = cls().detect(doc)
                for f in found:
                    f.origin = f"context:{i}"
                findings.extend(found)
        score = calculate_risk_score(findings)
        return ScanOutcome(decision=decide(findings, score, policy=self._policy),
                           risk_score=score, findings=findings)

    def check_tool_call(self, name: str, arguments: dict) -> ScanOutcome:
        """Two independent checks, most-severe-wins: deterministic
        name-based authorization, and content scanning of the serialized
        arguments. The model never decides its own authorization."""
        import json

        findings: list[Finding] = []
        for cls in get_registered_detectors().values():
            found = cls().detect(json.dumps(arguments))
            for f in found:
                f.origin = f"tool_arguments:{name}"
            findings.extend(found)

        score = calculate_risk_score(findings)
        content = decide(findings, score, policy=self._policy)
        final = most_severe([content, authorize_tool(name)])
        return ScanOutcome(decision=final, risk_score=score, findings=findings)

    def guard(self, text: str, *, origin: str = "input") -> ScanOutcome:
        """Like scan(), but raises Blocked when the action should not
        proceed. For callers who prefer fail-fast over branching."""
        outcome = self.scan(text, origin=origin)
        if not outcome.allowed:
            raise Blocked(outcome)
        return outcome

    # -------------------------------------------------------- integrations

    def middleware(self, *, field: str = "text", on_block: Callable | None = None):
        """ASGI/Starlette middleware factory for an existing application.

        Scans `field` in a JSON request body and short-circuits with 400
        when blocked. Deliberately narrow: it does not try to infer where
        user text lives in an arbitrary schema, because guessing wrong in
        a security control is worse than requiring one line of config.
        """
        import json as _json

        guard = self

        async def _mw(request, call_next):
            if request.method in ("POST", "PUT", "PATCH"):
                body = await request.body()
                try:
                    payload = _json.loads(body) if body else {}
                except _json.JSONDecodeError:
                    payload = {}
                text = payload.get(field)
                if isinstance(text, str) and text.strip():
                    outcome = guard.scan(text)
                    if not outcome.allowed:
                        if on_block:
                            return on_block(outcome)
                        from starlette.responses import JSONResponse

                        return JSONResponse(status_code=400, content={
                            "error": "blocked by SentinelCore",
                            "sentinelcore": outcome.to_dict(),
                        })
            return await call_next(request)

        return _mw

    def __repr__(self) -> str:
        return f"Guard(policy={self._policy_name!r})"
