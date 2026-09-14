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
from dataclasses import fields as _dc_fields
from dataclasses import replace as _dc_replace
from typing import Any, Callable

from sentinelcore.core.context import detector_selection
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


from sentinelcore import presets as _presets


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
            self.preset = _presets.get(policy)   # raises ValueError on unknown
            self._policy_name = policy
        else:
            # Dict form overrides individual preset fields. The previous
            # version stored the dict in self._overrides and never read it,
            # so Guard(policy={...}) silently behaved as "balanced" -- an
            # API that accepts configuration and ignores it.
            base = _presets.get(_presets.DEFAULT)
            unknown = set(policy) - {f.name for f in _dc_fields(_presets.Preset)}
            if unknown:
                raise ValueError(f"unknown policy field(s): {sorted(unknown)}")
            self.preset = _dc_replace(base, name="custom", **policy)
            self._policy_name = "custom"

        self._policy = load_policy()
        # A preset that does not change behaviour is decoration. Provenance
        # rules are the one policy knob the ablation showed to matter, so
        # presets that disable them must actually disable them.
        if not self.preset.provenance_rules:
            self._policy = {**self._policy, "origin_rules": {}}
        # Detector enablement is held PER GUARD and applied only for the
        # duration of a call. An earlier version set it on the global
        # settings object at construction time, which leaked into every
        # other consumer in the process -- a library that mutates global
        # state when you instantiate it will interfere with its host
        # application, and it broke seven unrelated tests before it was
        # caught. See _active() below.
        self._want_ml = enable_ml if enable_ml is not None else self.preset.requires_ml
        self._want_semantic = enable_semantic if enable_semantic is not None else False

    # ---------------------------------------------------------------- core

    def _active(self):
        """Scopes this Guard's detector selection to the current call.

        Uses a ContextVar rather than mutating global settings. The
        previous implementation saved and restored the global flags, which
        interleaves under concurrency: measured at 531 of 800 scans running
        with the wrong detector configuration when two presets ran
        concurrently, with the global flag left permanently wrong. See
        sentinelcore/core/context.py.
        """
        return detector_selection(ml_detector=self._want_ml, semantic_detector=self._want_semantic)

    def scan(self, text: str, *, origin: str = "input") -> ScanOutcome:
        """Scan one piece of text. `origin` is the provenance class and it
        affects the outcome -- see docs/research/README.md; passing the
        default for retrieved content silently discards that signal."""
        findings: list[Finding] = []
        with self._active():
            for cls in get_registered_detectors().values():
                found = cls().detect(text)
                for f in found:
                    f.origin = origin
                findings.extend(found)

        score = calculate_risk_score(findings)
        decision = decide(findings, score, policy=self._policy)
        outcome = ScanOutcome(decision=decision, risk_score=score, findings=findings)

        if decision == Decision.SANITIZE and self.preset.sanitize:
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
        with self._active():
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
        with self._active():
            for cls in get_registered_detectors().values():
                found = cls().detect(json.dumps(arguments))
                for f in found:
                    f.origin = f"tool_arguments:{name}"
                findings.extend(found)

        score = calculate_risk_score(findings)
        content = decide(findings, score, policy=self._policy)
        # Tool authorization is what the ablation showed to carry the
        # structural-attack category; a preset that turns it off is a real
        # reduction in coverage, not a tuning detail.
        candidates = [content]
        if self.preset.tool_authorization:
            candidates.append(authorize_tool(name))
        final = most_severe(candidates)
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

    def operating_point(self) -> str:
        """What this configuration measured on the agent benchmark. Not a
        guarantee about your traffic -- see sentinelcore/presets.py."""
        return self.preset.summary()

    def __repr__(self) -> str:
        return f"Guard(policy={self._policy_name!r})"
