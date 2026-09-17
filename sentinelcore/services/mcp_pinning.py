"""
MCP tool-definition pinning and change detection.

THE ATTACK THIS ADDRESSES
An MCP server's tool descriptions are sent to the model as instructions.
A server can be benign when a developer installs and reviews it, then
change its tool descriptions afterwards -- the documented "rug pull".
Neither a one-shot pre-deployment scan nor the runtime content gateway
sees this: the scan already happened, and the new description may contain
nothing the detectors flag. What is anomalous is not the text. It is the
CHANGE.

APPROACH
Fingerprint each tool definition, store it, and compare on every
subsequent observation. Fingerprints are computed over a CANONICAL form
(sorted keys, normalised whitespace) so reformatting a config file does
not look like an attack -- a detector that cries wolf on whitespace gets
turned off.

TRUST ON FIRST USE, stated plainly
The first observation establishes the baseline. If a server was ALREADY
poisoned when first pinned, that state becomes the trusted baseline and
this mechanism will never report it. TOFU detects change, not badness.
It is complementary to `sentinel assess`, which inspects content -- run
both. This limitation is surfaced in the API response and the CLI output
rather than left in a docstring.

SEVERITY, and why description changes outrank everything
  description_changed  HIGH     the rug-pull signature; description text
                                reaches the model as instructions
  schema_changed       HIGH     changes what arguments the model will send
  tool_added           MEDIUM   new capability appearing without review
  tool_removed         INFO     a capability going away is not an attack
                                on the host, though it may break it
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sentinelcore.storage import get_store

logger = logging.getLogger(__name__)


class ChangeType(str, Enum):
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    DESCRIPTION_CHANGED = "description_changed"
    SCHEMA_CHANGED = "schema_changed"


SEVERITY = {
    ChangeType.DESCRIPTION_CHANGED: "high",
    ChangeType.SCHEMA_CHANGED: "high",
    ChangeType.TOOL_ADDED: "medium",
    ChangeType.TOOL_REMOVED: "info",
}


def canonical(definition: dict) -> str:
    """Stable serialisation of a tool definition.

    Only the fields that affect model behaviour are included: name,
    description and inputSchema. A server adding a `version` field or
    reordering keys is not a security event, and treating it as one
    trains operators to ignore the alerts that matter.
    """
    subset = {
        "name": definition.get("name", ""),
        "description": " ".join((definition.get("description") or "").split()),
        "inputSchema": definition.get("inputSchema") or definition.get("input_schema") or {},
    }
    return json.dumps(subset, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(definition: dict) -> str:
    return hashlib.sha256(canonical(definition).encode("utf-8")).hexdigest()[:32]


def _parts(definition: dict) -> tuple[str, str]:
    """Description and schema fingerprints separately, so a change can be
    attributed rather than reported as an opaque 'something differs'."""
    desc = " ".join((definition.get("description") or "").split())
    schema = definition.get("inputSchema") or definition.get("input_schema") or {}
    return (
        hashlib.sha256(desc.encode("utf-8")).hexdigest()[:16],
        hashlib.sha256(json.dumps(schema, sort_keys=True).encode("utf-8")).hexdigest()[:16],
    )


_TOFU_NOTE = (
    "Trust on first use: the first observation becomes the baseline. A server that was ALREADY "
    "poisoned when pinned will never be reported by this check. It detects change, not badness "
    "-- run 'sentinel assess' or POST /api/v1/scan/mcp-tools to inspect content."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def pin_tools(server: str, tools: list[dict]) -> dict[str, Any]:
    """Establishes or refreshes the baseline for a server.

    Explicit and destructive to prior state by design: re-pinning after a
    detected change is how an operator says "I reviewed this and accept
    it". It must be a deliberate act, never automatic -- a system that
    silently re-pins on change detects nothing.
    """
    store = get_store()
    pinned = []
    for t in tools:
        name = t.get("name")
        if not name:
            continue
        store.upsert_mcp_pin(str(uuid.uuid4()), server, name, fingerprint(t),
                             canonical(t), _now())
        pinned.append(name)
    return {"server": server, "pinned": sorted(pinned), "count": len(pinned)}


def check_tools(server: str, tools: list[dict], record: bool = True) -> dict[str, Any]:
    """Compares an observed tool list against the pinned baseline.

    `record=False` makes this a pure query -- used by tests and dry runs so
    that inspecting for changes does not itself mutate history.
    """
    store = get_store()
    existing = {p["tool_name"]: p for p in store.list_mcp_pins(server)}
    observed = {t["name"]: t for t in tools if t.get("name")}

    # No baseline means nothing to compare against. Reporting every tool as
    # "added" would flood an operator with alarms on first run and mislabel
    # the state: the honest answer is that this server has never been
    # pinned, not that it changed.
    if not existing:
        return {
            "server": server, "pinned_tools": 0, "observed_tools": len(observed),
            "changes": [], "status": "unpinned",
            "limitation": _TOFU_NOTE,
            "next_step": f"run 'sentinel mcp pin --server {server}' to establish a baseline",
        }

    changes: list[dict] = []

    def add(name, ctype: ChangeType, summary, old=None, new=None):
        changes.append({
            "server": server, "tool_name": name, "change_type": ctype.value,
            "severity": SEVERITY[ctype], "summary": summary,
            "old_fingerprint": old, "new_fingerprint": new, "detected_at": _now(),
        })

    for name, tool in observed.items():
        pin = existing.get(name)
        new_fp = fingerprint(tool)
        if pin is None:
            add(name, ChangeType.TOOL_ADDED,
                f"Tool '{name}' was not present at the last pin.", None, new_fp)
            continue
        if pin["fingerprint"] == new_fp:
            continue
        try:
            old_def = json.loads(pin["definition"])
        except (json.JSONDecodeError, TypeError):
            old_def = {}
        old_desc, old_schema = _parts(old_def)
        new_desc, new_schema = _parts(tool)
        if old_desc != new_desc:
            add(name, ChangeType.DESCRIPTION_CHANGED,
                f"The description of '{name}' changed after it was pinned. Tool descriptions "
                "are delivered to the model as instructions.", pin["fingerprint"], new_fp)
        if old_schema != new_schema:
            add(name, ChangeType.SCHEMA_CHANGED,
                f"The input schema of '{name}' changed after it was pinned, altering what "
                "arguments the model will send.", pin["fingerprint"], new_fp)
        if old_desc == new_desc and old_schema == new_schema:
            # Fingerprint differs but neither attributable part did. Report
            # it rather than hide it -- an unexplained difference in a
            # security baseline is itself worth surfacing.
            add(name, ChangeType.SCHEMA_CHANGED,
                f"The definition of '{name}' changed in a way this check could not attribute "
                "to description or schema.", pin["fingerprint"], new_fp)

    for name, pin in existing.items():
        if name not in observed:
            add(name, ChangeType.TOOL_REMOVED,
                f"Tool '{name}' was pinned but is no longer offered.", pin["fingerprint"], None)

    if record and changes:
        for ch in changes:
            store.record_mcp_change(str(uuid.uuid4()), **ch)

    return {
        "server": server,
        "pinned_tools": len(existing),
        "observed_tools": len(observed),
        "changes": changes,
        "status": "changed" if changes else "clean",
        "limitation": _TOFU_NOTE,
    }


def unacknowledged_changes(limit: int = 100) -> list[dict]:
    return get_store().list_mcp_changes(acknowledged=False, limit=limit)


def acknowledge(change_id: str, by: str = "") -> bool:
    """Marks a change reviewed. Does NOT re-pin: accepting that a change
    happened is a different decision from trusting the new definition."""
    return get_store().acknowledge_mcp_change(change_id)
