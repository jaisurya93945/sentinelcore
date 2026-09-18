# Identity and tenant isolation

## Configuration

```bash
SENTINELCORE_API_KEYS="key:role"                      # tenant 'default'
SENTINELCORE_API_KEYS="key:role:tenant"               # named tenant
SENTINELCORE_API_KEYS="key:role:tenant:principal_id"  # named actor
```

All three forms are valid. **An existing `key:role` configuration keeps working unchanged** and lands in the `default` tenant.

Where no principal id is given, a non-reversible fingerprint of the key is used. **The raw key never reaches an audit record, an alert, or a log** — a security tool that writes its own credentials into its audit trail has created the problem it exists to prevent.

An unrecognised role is **rejected, not defaulted**, so a typo removes access rather than silently granting it.

## `decided_by` is now a fact, not a claim

Approval decisions previously recorded a caller-supplied string. The schema said UNVERIFIED and the dashboard said so in its own prompt — honest, but it meant **an approval record whose "who" could be forged**.

The deciding principal now comes from the authenticated credential. The request-body field is ignored, kept only so existing callers do not break, and a test asserts a caller passing `impersonated@attacker` is still recorded as their real principal.

## Tenant is ambient, not a parameter

Passing a tenant into each storage call means one forgotten call site is a cross-tenant leak. The tenant lives in a `ContextVar` — isolated per thread *and* per asyncio task — bound once by middleware for the whole request, and read internally by the storage backends.

Middleware rather than a route dependency, deliberately: **every** path must bind a principal, including endpoints that declare no role requirement. A handler reached without one would read the default tenant's data.

### The control that keeps it true

Ambient scoping stops a *call site* omitting the tenant. Nothing stops someone writing a new `SELECT` that forgets the predicate — so `test_tenancy.py` parses the backend source and **fails CI on any statement touching a tenant-scoped table without a tenant predicate**, and on any insert missing the tenant column.

**It is parametrised over both backends.** The first version of the check covered SQLite only, and PostgreSQL shipped completely unscoped underneath it for one commit. An abstraction whose two implementations have *different security properties* is the worst state for an abstraction to be in, because callers cannot reason about it at all — so parity is now asserted three ways: the predicate check, an insert check, and a test that neither backend leaves an abstract method unimplemented.

For that check to work the predicate must be in the *literal* SQL rather than appended at runtime. One query built its `WHERE` clause dynamically; it was rewritten. **A security control that cannot be verified statically is weaker than one that can, even when both are correct today.**

## A real isolation bug this work found

The first version of migration 5 created a tenant-scoped unique index on `mcp_pins` and left the old `UNIQUE(server, tool_name)` index in place, describing it as harmless.

**That was wrong.** The old index enforces *global* uniqueness, so two tenants that both pin a server named `kb` collide — one silently overwrites the other's baseline. Exactly the unsafe partial isolation this milestone exists to prevent. A test caught it.

The old index is now dropped. That required narrowing the non-destructive migration rule, with the reasoning recorded in the code: **`DROP INDEX` removes no data.** An index is derived entirely from the rows and rebuilding it loses nothing, whereas `DROP TABLE` and `DROP COLUMN` destroy data irrecoverably. Conflating the two forced a genuine correctness fix to be avoided rather than made.

## Adversarial checks performed

| Attempt | Result |
|---|---|
| Tenant name containing `' OR '1'='1` | 0 rows — all predicates parameterised |
| Empty or whitespace tenant in config | Falls back to `default` |
| Table names in retention `DELETE` | Hardcoded tuple, never user-controlled |
| Nested `acting_as` scopes | Restore correctly on exit |

## Upgrade path

Migrations 4 and 5 are additive. Existing rows backfill to `default`. Verified on a genuine v3 database with rows written the way v3 code wrote them: **legacy data intact, visible in `default`, invisible to any other tenant.**

## Status and limits

| | Status |
|---|---|
| Principal derivation, tenant scoping, isolation | **TESTED** — 16 tests including cross-tenant read, decide, attach, retention and pin-collision attempts |
| Upgrade from pre-tenancy database | **TESTED** |
| PostgreSQL parity | **IMPLEMENTED, NOT INTEGRATION-TESTED** — every query is tenant-scoped and the static check runs against both backends, but the 13 integration tests **skip** without a live server. No PostgreSQL server was reachable in the development environment |
| SSO / OIDC / user management | **NOT PLANNED** — SentinelCore is not an identity provider. Principals come from the credential already presented |

**With authentication disabled there is no identity, and therefore no isolation.** Everything runs as one implicit principal in `default`. That is correct for local use, and it is why `sentinel assess` reports disabled authentication as a HIGH finding.
