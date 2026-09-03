# SentinelCore — Final Industry-Grade Hardening & Validation Master Prompt

This is the source document being worked through in `docs/hardening/STATUS.md`, saved verbatim (not summarized) so the audit trail is traceable — anyone reading the status doc can check it against what's actually here, not take a summary's word for it. Provided by the project owner on 2026-08-22.

Being saved doesn't mean every section will be attempted. `STATUS.md` states plainly which sections are done, partial, or explicitly declined, and why — consistent with this document's own instruction: "Do not turn 'planned' into 'supported.'"

---

You are working on the existing SentinelCore repository.

The project has already gone through multiple development iterations and is currently being described as "complete."

Do NOT accept that claim at face value.

Your job is to independently audit the current repository and close the remaining gaps between the current implementation and a genuinely mature, production-oriented AI security gateway.

This is NOT a request to blindly add features.

The objective is:

Make SentinelCore demonstrably secure, reliable, testable, observable, deployable, and defensible as an open-source AI security gateway.

Do not optimize for feature count.

Do not optimize for README appearance.

Do not declare success because the project contains many modules.

The final standard is:

Show me the implementation. Show me the tests. Show me the evidence.

---

## 1. Current Project Context

SentinelCore is intended to provide a provider-independent security gateway covering the AI interaction lifecycle:

```
Application
    |
SentinelCore
    |
Input Security
    |
RAG / Context Security
    |
Agent / Tool Security
    |
MCP Security
    |
Risk Engine
    |
Policy Engine
    |
Reverse Proxy
    |
LLM Provider
    |
Streaming / Output Security
    |
Audit / Observability
    |
Application
```

The repository already contains substantial functionality including: modular detectors, prompt-injection detection, obfuscation detection, risk scoring, policy enforcement, RAG/context scanning, PII detection, secret detection, output scanning, agent/tool security, MCP tool-discovery security, reverse proxy, streaming inspection, audit logging, dashboard, Docker, CI, dependency scanning, evaluation framework, regression testing.

Preserve working architecture. Do not rewrite working components without a concrete engineering reason.

## 2. Non-Negotiable Authenticity Rule

Never fabricate: benchmark results, accuracy, recall, precision, F1, latency, throughput, security coverage, provider compatibility, MCP compatibility, production readiness, test results, screenshots, attack-detection rates.

If something cannot be verified, say: NOT IMPLEMENTED / PARTIALLY IMPLEMENTED / EXPERIMENTAL / UNVERIFIED / PLANNED.

Do not turn "planned" into "supported." Do not turn "tests exist" into "tests pass." Do not turn "Docker configuration exists" into "Docker was successfully validated." Do not turn "MCP scanner exists" into "MCP gateway security is complete."

## 3. First: Freeze and Audit the Current State

Before making changes, inspect: the entire repository, Git history, all source code, all tests, CI, Docker configuration, dependency files, evaluation datasets, benchmark scripts, audit system, dashboard, reverse proxy, streaming implementation, agent/tool security, MCP implementation, documentation, CAPABILITY_MATRIX.md, SECURITY.md, threat model, roadmap.

Then create a concrete gap analysis. Do not begin coding until you understand what already exists.

## 4. Current Claims Must Be Verified

For every capability currently claimed: Claim -> Implementation -> Automated test -> Integration test where appropriate -> Real execution evidence.

Classify each capability: VERIFIED (implementation exists and was successfully tested) / PARTIALLY VERIFIED (implementation exists but meaningful validation is incomplete) / UNVERIFIED (implementation exists but evidence is missing) / NOT IMPLEMENTED (capability does not actually exist).

Update the capability matrix accordingly.

## 5. Authentication

This is a priority. Protect every security-sensitive endpoint. Implement a proper authentication mechanism for: proxy access, scanning APIs, audit APIs, dashboard, administration, configuration.

Requirements: secure credential handling, key rotation, revocation where applicable, authentication failure handling, secure defaults, no hard-coded credentials, no secrets in logs, no secrets in Git.

Do not expose administrative functionality anonymously.

## 6. Authorization

Authentication alone is insufficient. Implement authorization for: users, services, administrators, tenants, providers, tools, MCP servers.

Support least privilege. Examples: Viewer, Auditor, Operator, Administrator, Service.

Do not create unnecessary privilege.

## 7. Rate Limiting and Resource Protection

Protect SentinelCore itself. Implement appropriate limits for: requests, concurrent requests, body size, context size, response size, stream duration, tool calls, MCP operations, audit storage.

Protect against: denial of service, oversized prompts, expensive requests, malicious tool loops, recursive agent behavior, excessive streaming, resource exhaustion.

All limits must be configurable.

## 8. Reverse Proxy Hardening

The proxy is one of SentinelCore's most important components. Verify: upstream validation, timeout behavior, connection handling, retry behavior, circuit breakers, health checks, cancellation, client disconnect handling, upstream disconnect handling, malformed responses, malformed requests, oversized bodies, header handling, request IDs, correlation IDs, provider abstraction, provider-specific behavior isolation.

Determine explicitly: when a security component fails, does SentinelCore fail-open or fail-closed? The behavior must be intentional and documented.

## 9. Streaming Security

The existing streaming implementation must be hardened. Verify: SSE parsing, partial chunks, token boundaries, UTF-8 boundaries, split secrets, split PII, split malicious instructions, malformed SSE, upstream disconnects, client disconnects, cancellation, mid-stream policy violations.

Avoid unnecessary O(n^2) rescanning. Where possible implement incremental stateful scanning.

Measure: streaming latency, memory usage, CPU overhead, throughput. Do not publish numbers until actually measured.

## 10. Input Security

Strengthen the deterministic security layer. Cover: direct prompt injection, indirect prompt injection, instruction hierarchy attacks, role manipulation, system prompt extraction, delimiter attacks, encoding attacks, Unicode attacks, homoglyphs, invisible characters, multilingual attacks, obfuscation, multi-turn attacks, instruction laundering, contextual attacks.

Do not solve every problem with regex. Keep deterministic rules where they provide reliable value.

## 11. RAG Security

Treat all retrieved content as untrusted. Inspect: documents, chunks, metadata, source information, embedded instructions, citations, retrieval context.

Protect against: poisoned documents, indirect prompt injection, instruction conflicts, retrieval manipulation, malicious metadata, cross-document attacks.

Preserve provenance. A finding should identify whether it originated from: user input, system input, RAG context, tool argument, tool result, MCP metadata, MCP result, LLM output.

## 12. Agent Security

Strengthen agent security beyond individual tool calls. Inspect: tool name, tool description, arguments, tool response, session, agent identity, user identity, cumulative risk.

Implement: allowlists, denylists, tool-specific policies, sensitive-tool restrictions, destructive-action restrictions, human approval, argument validation, response inspection.

## 13. Multi-Step Agent Security

Add contextual analysis for sequences such as: search -> retrieve sensitive information -> transform -> send externally.

The system must be able to represent: action history, tool chain, cumulative risk, privilege escalation, data movement, destination changes, sensitive-data propagation.

Do not claim full agent reasoning unless actually implemented.

## 14. MCP Security

Move from static MCP scanning toward actual MCP gateway security. Support where appropriate: MCP Client -> SentinelCore -> MCP Server.

Inspect discovery (tool names, descriptions, schemas, nested properties, metadata, tool poisoning, suspicious instructions), tool invocation (tool name, arguments, metadata, identity, session, origin), and tool response (treat as untrusted: content, instructions, secrets, PII, injection attempts, malicious payloads).

## 15. MCP Authorization

Implement secure MCP authorization according to the applicable MCP specification and accepted OAuth security practices. Pay attention to: token validation, issuer validation, audience validation, scope validation, least privilege, token passthrough prevention, server identity, client identity, credential storage, authorization failures.

Do not invent security protocols.

## 16. Output Security

Strengthen output inspection. Inspect for: PII, secrets, credentials, system prompt leakage, internal information, policy violations, unsafe content where appropriate.

Support: ALLOW, WARN, BLOCK, SANITIZE, HUMAN_APPROVAL.

## 17. Real Sanitization

If the policy engine says SANITIZE, the system must actually perform a safe transformation. Examples: secret redaction, PII redaction, sensitive field removal, tool argument filtering, unsafe content removal.

Record: what happened, why, which policy triggered it, which component performed it.

Never claim sanitization is perfect.

## 18. Risk Engine

Review the risk model. Ensure risk calculations are: deterministic, explainable, configurable, testable.

Signals may include: detector, severity, confidence, origin, cumulative risk, tool sensitivity, data sensitivity, action sensitivity.

Do not call a risk score a probability unless it is statistically calibrated.

## 19. Policy Engine

Make policy evaluation robust. Policies should support: detector, severity, confidence, origin, endpoint, provider, user, tenant, tool, MCP server, data classification, action type.

Actions: ALLOW, WARN, BLOCK, SANITIZE, HUMAN_APPROVAL.

Policies must be: deterministic, testable, explainable, versionable, configurable.

## 20. Audit Security

Audit metadata without unnecessarily storing sensitive raw content. Record: request ID, scan ID, timestamp, session, actor, tenant, endpoint, provider, action, decision, risk score, detector, severity, origin, tool, MCP server, policy, streaming event.

Implement: pagination, filtering, retention, rotation, export, failure handling, integrity considerations.

## 21. Database Maturity

Review the current audit database. Implement where appropriate: schema versioning, migrations, indexes, retention, cleanup, backup considerations, corruption handling, concurrent access handling.

Do not rely on "delete the database and recreate it" as a production migration strategy.

## 22. Observability

The dashboard should evolve from a simple event viewer into useful security/operations observability. Include: request volume, block rate, warning rate, risk distribution, detector activity, attack categories, provider failures, latency, throughput, tool calls, MCP calls, streaming violations, audit failures, rate-limit events.

Never expose raw secrets or sensitive content through the dashboard.

## 23. Multi-Tenancy

If SentinelCore is intended to support multiple applications or customers: implement proper tenant isolation. Ensure: tenant-specific credentials, tenant-specific policies, tenant-specific audit access, tenant-specific rate limits, tenant-specific provider configuration.

Prevent cross-tenant access. If full multi-tenancy is not appropriate for the current architecture, document it explicitly rather than creating unsafe partial isolation.

## 24. Secret Management

Secure SentinelCore's own secrets. Never store provider keys directly in: source code, logs, audit database, screenshots, Git history.

Support secure configuration through environment variables or a proper secrets-management abstraction. Document key rotation.

## 25. Supply-Chain Security

Go beyond dependency scanning. Where practical implement: pinned dependencies, dependency review, vulnerability scanning, secret scanning, SBOM, container scanning, static analysis, reproducible builds, signed artifacts, provenance/attestation.

Do not claim full supply-chain security unless the controls are actually implemented.

## 26. Container Security

Review Docker from an attacker perspective. Verify: non-root execution, minimal image, minimal packages, no unnecessary capabilities, read-only filesystem where practical, dropped Linux capabilities where appropriate, secure environment handling, health checks, resource limits, no debug mode, no exposed administrative ports by default.

## 27. API Security

Fuzz and test every endpoint. Include: malformed JSON, missing fields, unexpected fields, wrong types, huge values, deeply nested objects, invalid headers, invalid authentication, authorization failures, rate-limit behavior, request cancellation, duplicate parameters, malformed SSE.

## 28. Real Provider Validation

Create optional integration tests for real providers. Never commit credentials. Real-provider tests must: be opt-in, be clearly documented, be safe, be isolated from unit tests.

Test: request forwarding, response forwarding, streaming, blocked requests, output blocking, provider failures, rate limits, timeouts.

If real providers are unavailable, clearly mark them UNVERIFIED.

## 29. Load and Performance Testing

Create reproducible benchmarks. Measure: p50/p95/p99 latency, requests/sec, concurrent connections, CPU, memory, streaming overhead, scanning overhead, audit overhead, proxy overhead.

Test: small prompts, large prompts, large RAG contexts, long outputs, streaming, tools, MCP.

Never fabricate results.

## 30. Chaos / Failure Testing

Test: upstream timeout, upstream 429, upstream 500, upstream disconnect, malformed response, malformed SSE, slow provider, client disconnect, audit database failure, detector exception, policy exception, MCP failure, tool timeout, tool response failure.

Document expected behavior for each.

## 31. Security Regression Corpus

Maintain a versioned security corpus. Categories: prompt injection, jailbreaks, obfuscation, Unicode, multilingual attacks, RAG poisoning, agent attacks, tool attacks, MCP attacks, PII, secrets, output attacks, streaming attacks, malformed requests.

Maintain: training data, validation data, held-out test data. Never tune against the final held-out set.

## 32. Dataset Provenance

For every external dataset document: source, license, version/date, number of samples, labels, categories, preprocessing, duplicates, splits, limitations, contamination concerns.

Keep historical evaluation datasets immutable. Never silently change the benchmark.

## 33. Evaluation

The current 744-example benchmark must remain a historical baseline. Do not overwrite it. Track results by release: v0.x, v1.x, v2.x, ...

Measure: precision, recall, F1, FPR, attack coverage, category-specific performance, regressions.

Then create a broader held-out evaluation set.

## 34. Ablation Studies

Measure the value of individual components. Examples: Rules only / Rules + Obfuscation / Rules + RAG / Rules + Agent / Rules + MCP / Rules + Output / Full SentinelCore.

Measure: recall, precision, FPR, F1, latency, resource usage.

This should become the foundation of the eventual research paper.

## 35. Semantic / ML Detection

Do NOT add an LLM just for marketing. First determine exactly where deterministic methods fail. Then optionally implement: Deterministic detectors + Semantic detector -> Risk Engine -> Policy Engine.

Compare: deterministic baseline, semantic model, combined system. The model must demonstrate measurable improvement before becoming part of the default path.

## 36. Future Custom LLM

Do not train a custom LLM inside this hardening phase unless required. A future independent project can train a model from scratch, later evaluated against SentinelCore.

The experiment should be: SentinelCore baseline vs SentinelCore + custom security model. Measure: recall, precision, FPR, F1, latency, memory, cost, attack-category performance.

No integration should be justified without evidence.

## 37. Security Testing

Implement meaningful: SAST, dependency scanning, secret scanning, API fuzzing, property-based testing where useful, malformed-input testing, proxy testing, streaming testing, MCP testing, agent testing, regression testing.

The goal is coverage of actual failure modes. Do not add security tools merely for badges.

## 38. Threat Model

Update the threat model for: malicious users, malicious applications, poisoned RAG documents, malicious tool servers, malicious MCP servers, compromised providers, compromised dependencies, malicious tool results, malicious model outputs, insider threats, tenant isolation attacks, denial of service, supply-chain attacks.

For every threat document: attacker, asset, attack path, mitigation, residual risk.

## 39. Security Disclosure Lifecycle

Make the project maintainable as a real security project. Ensure the repository contains: SECURITY.md, vulnerability reporting process, supported versions, security response expectations, responsible disclosure guidance, security advisory process, patch/release procedure.

Do not invent response-time guarantees.

## 40. Release Engineering

Create release gates. A release cannot be called production-ready unless: full tests pass, dependencies resolve, Docker builds, security scans pass, proxy works, streaming works, audit works, authentication works, authorization works, security regression tests pass, known limitations are documented, documentation matches implementation, performance claims are backed by measurements.

## 41. Backward Compatibility

Avoid unnecessary breaking changes. If a breaking change is necessary: document it, provide migration instructions, update versioning, update tests, update API documentation.

## 42. Documentation Cleanup

Audit every README claim. For every sentence saying: supports, protects, detects, prevents, production-ready, secure, industry-grade, high performance — ask "what evidence proves this?" If there is no evidence, rewrite the claim.

Keep architecture, threat model, capability matrix, API docs, deployment docs, configuration docs, limitations, benchmark methodology, dataset provenance, and roadmap synchronized with the code.

## 43. Industry-Readiness Gate

At the end, calculate separate scores. Do NOT collapse everything into one percentage. Provide: Feature completeness, Security maturity, Reliability maturity, Performance maturity, Operational maturity, Research maturity, Evidence maturity.

Do not call the system "industry-grade" unless the evidence supports that conclusion.

## 44. Final Red-Team Review

Before declaring completion, act as an attacker. Try to bypass: input detection, RAG detection, tool policies, MCP policies, output scanning, streaming scanning, authentication, authorization, rate limits, tenant isolation, audit controls.

Attempt: malformed requests, huge requests, encoded attacks, Unicode attacks, semantic paraphrases, multi-step attacks, tool poisoning, MCP poisoning, malicious tool responses, streaming split attacks, credential leakage, provider abuse.

Record every successful bypass. Do not hide failures. Turn meaningful findings into regression tests.

## 45. Final Deliverable

When you believe the project is complete, produce: Executive summary, Architecture, Implemented capabilities (only verified), Security controls, Test results (actual only), Benchmark results (actual only), Performance results (actual only), Red-team results, Known limitations (brutally honest), Remaining gaps, Industry-readiness assessment (separate maturity categories), Research readiness.

## 46. Final Principle

The goal is NOT "Make Claude say SentinelCore is complete." The goal is: Make SentinelCore difficult to criticize technically because the implementation, testing, documentation, measurements, threat model, and limitations all agree with each other.

If something cannot be proven, leave it unproven. If something is incomplete, say it is incomplete. If a feature is unnecessary, do not add it. If an existing implementation is already correct, preserve it. If a proposed improvement makes the architecture worse, reject the improvement and explain why.

Prioritize: Security correctness > Reliability > Evidence > Performance > Maintainability > Features > Marketing.

Work incrementally. Create focused commits for major changes. Run tests after each milestone. Do not rewrite the entire project in one pass.

At the end, SentinelCore should be a serious, reproducible, provider-independent AI security gateway, not merely a large collection of security features.
