# MCP definition pinning

```bash
sentinel mcp pin   --server kb --file tools.json   # establish the baseline
sentinel mcp check --server kb --file tools.json   # compare against it
sentinel mcp changes                               # unacknowledged changes
```

Exit codes: **0** clean · **1** low/medium change · **2** high-severity change.

## The attack

An MCP server's tool descriptions are delivered to the model **as instructions**. A server can be benign when a developer installs and reviews it, then change its descriptions afterwards — the documented "rug pull".

Neither existing control sees this. The pre-deployment assessment already ran. The runtime content gateway inspects text, and the new description may contain nothing its detectors flag. **What is anomalous is not the text — it is the change.**

## Severity, and why descriptions outrank everything

| Change | Severity | Why |
|---|---|---|
| `description_changed` | **HIGH** | The rug-pull signature. Description text reaches the model as instructions. |
| `schema_changed` | **HIGH** | Alters what arguments the model will send. |
| `tool_added` | MEDIUM | New capability appearing without review. |
| `tool_removed` | INFO | May break the host, but is not an attack on it. |

## Fingerprints are computed over a canonical form

Sorted keys, normalised whitespace, and **only the fields that reach the model** (`name`, `description`, `inputSchema`). A server adding a `version` field or a developer reformatting a config file is not a security event. A detector that cries wolf on whitespace gets turned off, and then it detects nothing at all.

## Trust on first use — the limitation, stated in every response

The first observation establishes the baseline. **If a server was already poisoned when first pinned, that state becomes the trusted baseline and this mechanism will never report it.**

This detects *change*, not *badness*. It is complementary to `sentinel assess` and `POST /api/v1/scan/mcp-tools`, which inspect content. Run both.

That limitation is returned in every API response and printed by the CLI, not left in a docstring — a caller must not read `clean` as "this server is safe". A test asserts it is present.

## Re-pinning and acknowledgement are different decisions

**Re-pinning** (`ADMIN`) says *"I reviewed this change and I trust the new definition."* It replaces the baseline.

**Acknowledging** (`ADMIN`) says *"I have seen this alert."* It does **not** re-pin — a test asserts the change is still reported afterwards. Conflating them would turn review into approval, and an operator clearing an alert queue would silently bless every change they dismissed.

Re-pinning is admin-only for the same reason: letting the role that merely observes re-establish a baseline would allow a change to be blessed by whoever happened to notice it. Checking is operator-level, because observation should not require elevated rights.

## An unpinned server reports `unpinned`, not `changed`

The first version reported every tool as `tool_added` on a server with no baseline, producing `changed`. That would flood an operator with alarms on first run and mislabel the state. A server with no baseline now returns `unpinned` with zero changes and a next step.

## Integration

Detected changes flow into the existing alert path — a definition change is exactly the kind of event nobody is watching a dashboard for. They are also recorded durably (`mcp_changes`, schema v3) so an unacknowledged change survives a restart.

| | Status |
|---|---|
| Fingerprinting, change detection, pin lifecycle | **TESTED** — 22 tests |
| Storage (SQLite) | **TESTED** — migration v2→v3 upgrade verified with rows preserved |
| Storage (PostgreSQL) | **IMPLEMENTED, NOT INTEGRATION-TESTED** |
| Automatic periodic polling of live MCP servers | **PLANNED** — this package has no scheduler; run `sentinel mcp check` from cron or CI |
