# Pre-deployment assessment

```bash
sentinel assess .
sentinel assess . --json          # for CI
```

Exit codes: **0** clean or info-only · **1** low/medium · **2** high/critical.

## What it inspects

| Check | Finds |
|---|---|
| `secrets` | Credential-shaped values in source and configuration |
| `mcp_definitions` | MCP server configs and poisoned tool descriptions, including nested `inputSchema` properties |
| `tool_declarations` | Consequential tool names declared without an explicit authorization rule |
| `sentinelcore_config` | SentinelCore's own settings — auth off, rate limiting off, retention off, in-memory audit database, third-party data egress |

## What it cannot do — and why the report says so

Static analysis sees what is written down. It **cannot** see prompts assembled at runtime, tools registered dynamically, MCP servers discovered over the network, or anything that depends on data.

Every check declares its own blind spot in a `limitations` field, and both the human and JSON output print them. **A scanner that reports "0 issues" without saying what it never examined manufactures confidence**, which is worse than finding nothing. A test asserts every check declares limitations and that the word `CANNOT` appears in each.

This complements the runtime gateway. The gateway sees what static analysis cannot.

## False positives are managed, not hidden

The first run of this tool against **its own repository** flagged SentinelCore's benchmark fixtures as CRITICAL — a live instance of the over-defense failure measured in Finding 10. Three responses, in order of preference:

**1. Precision where it is cheap.** Known documentation placeholders (AWS's `...EXAMPLE` convention, `hunter2`, `user:pass`, `<angle-bracket>` templates) are **downgraded to INFO, never suppressed** — a real key containing a placeholder-like substring still appears.

**2. Path heuristics, downgraded not skipped.** Credentials under `tests/`, `fixtures/`, `examples/` become MEDIUM. Real keys do get pasted into tests; silently ignoring the location where that happens most often would be the wrong trade.

**3. Inline suppression, when a human has judged it.**

```python
KEY = "AKIA..."   # sentinel:ignore[secrets] -- fixture for the attack corpus
```

Scoped to a check, or bare for all checks on that line. Deliberately **not** a config file of glob patterns: those accumulate silently and end up excluding directories that once had one false positive. An inline comment is visible in review, travels with the line, and reappears in a diff when the line changes. Suppressions are **counted and reported**, so "0 findings, 47 suppressed" cannot be mistaken for a clean result.

## A defect found while building this

The consequential-tool check originally used word-boundary matching — `\bdelete\b`. That **cannot match inside `delete_everything`**, because `_` is a word character, so it missed snake_case, the dominant tool-naming convention. `send_email` only matched by accident, through a literal alternative in the pattern.

Replaced with tokenization that splits on separators *and* camelCase boundaries: `delete_everything`, `database.delete`, `deleteEverything` and `delete-all` all now yield the token `delete`, while `get_weather`, `read_file` and `list_files` remain unflagged.

## Bounds

Vendor directories (`node_modules`, `.venv`, `site-packages`, and 17 others) are never walked — scanning a virtualenv finds thousands of issues in code the developer cannot fix, which teaches people to ignore the tool. Files over 2MB and repositories over 20,000 files are capped, because an assessment tool that can be made to exhaust memory is the same defect class already found twice in this project.

A check that raises does not abort the run; it is recorded in `checks_skipped`. A partial report is useful, a crash is not.
