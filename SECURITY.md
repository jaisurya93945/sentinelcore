# Security Policy

SentinelCore is security-focused software still in early development (v0.x). No production security guarantees are made until v1.0.0 — see the "Current Status" table in `README.md` and `docs/CAPABILITY_MATRIX.md` for what is and isn't implemented today.

## Reporting a vulnerability

Please do not open a public issue for security vulnerabilities. Instead, report privately to: security@cipherai.in

(Replace with a monitored address before the first public release.)

## Scope

Vulnerabilities in SentinelCore's own code (the gateway, detectors, risk/policy engines, API, auth) are in scope. Vulnerabilities in third-party dependencies should also be reported upstream.

## Known, currently-unaddressed gaps

Not vulnerabilities in the traditional sense, but stated here so they aren't discovered by surprise: no rate limiting, no key rotation tooling, authentication is off by default. Full list in `docs/hardening/STATUS.md`.
