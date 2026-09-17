"""
The individual pre-deployment checks.

Each declares `limitations` -- what it cannot see -- and the report prints
them. A scanner reporting "0 issues" without saying what it never examined
is worse than one that finds nothing, because it manufactures confidence.
"""

import json
import re
from pathlib import Path

from sentinelcore.assess.base import (CONFIG_SUFFIXES, AssessmentFinding, Check, CheckResult,
                                      Severity, read_text, suppressed)


class SecretsCheck(Check):
    id = "secrets"
    title = "Hardcoded credentials in source and configuration"
    limitations = (
        "Pattern-based. Finds credentials matching known shapes (AWS keys, private key blocks, "
        "connection strings, JWTs). It CANNOT find credentials in formats it has no pattern for, "
        "values injected at build time, or secrets already committed to git history -- use a "
        "dedicated history scanner such as gitleaks for that. Known documentation placeholders "
        "are downgraded to INFO rather than suppressed, so a real key containing a placeholder-like "
        "substring is still reported."
    )

    # Paths where a credential-shaped string is usually a fixture rather than
    # a leak. Not skipped -- downgraded, because a real key does sometimes
    # get pasted into a test, and silently ignoring the location where that
    # happens most often would be the wrong trade.
    _LIKELY_FIXTURE = re.compile(r"(^|/)(tests?|fixtures?|examples?|docs?|samples?)/", re.I)

    # Credentials that are documented placeholders, not secrets. AWS's own
    # documentation uses keys ending in EXAMPLE by convention, and a handful
    # of joke passwords appear in every tutorial ever written.
    #
    # This list is narrow ON PURPOSE. Broad suppression is how a scanner
    # stops finding real credentials -- the first run of this very check
    # flagged this project's own benchmark fixtures as CRITICAL, which is
    # the over-defense failure mode measured elsewhere in this repository
    # (docs/research/README.md, Finding 10). The fix is precision, not a
    # wider ignore rule.
    #
    # Placeholders are DOWNGRADED to INFO, never suppressed: a real key that
    # happens to contain one of these substrings still appears in the report.
    _PLACEHOLDERS = re.compile(
        r"(EXAMPLE|AKIAIOSFODNN7|hunter2|changeme|your[-_]?(api[-_]?)?key|"
        r"xxxxx|placeholder|dummy|s3cr3t|password123|<[^>]+>|user:pass)", re.I)

    def run(self, root: Path, files: list[Path]) -> CheckResult:
        from sentinelcore.detectors.secrets.detector import SecretDetector

        detector = SecretDetector()
        result = CheckResult(check_id=self.id)
        for path in files:
            text = read_text(path)
            if text is None:
                continue
            result.files_examined += 1
            rel = str(path.relative_to(root))
            for i, line in enumerate(text.splitlines(), 1):
                if suppressed(line, self.id):
                    result.suppressed += 1
                    continue
                for f in detector.detect(line):
                    placeholder = bool(self._PLACEHOLDERS.search(line))
                    fixture = bool(self._LIKELY_FIXTURE.search("/" + rel))
                    if placeholder:
                        sev = Severity.INFO
                        note = (" It matches a known documentation placeholder "
                                "(e.g. an AWS ...EXAMPLE key), so it is reported for review "
                                "rather than as a leak.")
                    elif fixture:
                        sev = Severity.MEDIUM
                        note = " (in a test/example path -- verify it is a fixture)"
                    else:
                        sev = Severity.CRITICAL
                        note = ""
                    result.findings.append(AssessmentFinding(
                        check_id=self.id, severity=sev,
                        title=f"Possible {f.type.replace('_', ' ')} in source",
                        detail=f"A credential-shaped value appears in {rel}{note}.",
                        remediation=("Confirm it is a placeholder; if so, no action is needed."
                                     if placeholder else
                                     "Move it to an environment variable or a secret manager, then "
                                     "ROTATE it -- a committed credential must be assumed exposed."),
                        path=rel, line=i,
                        # The detector already redacts; never widen it here.
                        evidence=f.evidence.get("matched_text"),
                    ))
        return result


class MCPDefinitionCheck(Check):
    id = "mcp_definitions"
    title = "MCP server and tool definitions"
    limitations = (
        "Reads MCP config files found on disk. It CANNOT see servers configured through "
        "environment variables, tools discovered at runtime over the wire, or a server whose "
        "definition changes after installation -- that last case (a 'rug pull') is only "
        "detectable by runtime pinning, which SentinelCore does not yet implement."
    )

    _FILENAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json"}

    def run(self, root: Path, files: list[Path]) -> CheckResult:
        from sentinelcore.detectors.registry import get_registered_detectors

        result = CheckResult(check_id=self.id)
        detectors = {k: v for k, v in get_registered_detectors().items()
                     if k not in ("ml_classifier", "semantic")}

        candidates = [p for p in files if p.name.lower() in self._FILENAMES]
        if not candidates:
            result.skipped = "no MCP configuration files found"
            return result

        for path in candidates:
            text = read_text(path)
            if text is None:
                continue
            result.files_examined += 1
            rel = str(path.relative_to(root))
            try:
                data = json.loads(text)
            except json.JSONDecodeError as e:
                result.findings.append(AssessmentFinding(
                    check_id=self.id, severity=Severity.LOW,
                    title="Unparseable MCP configuration",
                    detail=f"{rel} is not valid JSON ({e.msg}), so its tools were not inspected.",
                    remediation="Fix the JSON so the file can be assessed.", path=rel))
                continue

            for desc, where in self._descriptions(data):
                for detname, cls in detectors.items():
                    for f in cls().detect(desc):
                        result.findings.append(AssessmentFinding(
                            check_id=self.id, severity=Severity.HIGH,
                            title=f"Suspicious content in MCP {where}",
                            detail=f"A tool description in {rel} contains {f.type}. Tool "
                                   "descriptions are sent to the model as instructions, so text "
                                   "here is executed as guidance, not displayed as documentation.",
                            remediation="Review the server's provenance and remove the instruction "
                                        "text. Treat third-party MCP servers as untrusted input.",
                            path=rel, evidence=str(f.evidence.get("matched_text"))[:80]))

            for name in self._server_names(data):
                result.findings.append(AssessmentFinding(
                    check_id=self.id, severity=Severity.INFO,
                    title=f"MCP server configured: {name}",
                    detail=f"{rel} configures the MCP server '{name}'. Its tools run with the "
                           "privileges of the host application.",
                    remediation="Confirm the server is one you control or trust. Scan its tool "
                                "list with POST /api/v1/scan/mcp-tools before enabling it.",
                    path=rel))
        return result

    def _server_names(self, data) -> list[str]:
        servers = data.get("mcpServers") or data.get("servers") or {}
        return list(servers) if isinstance(servers, dict) else []

    def _descriptions(self, node, where="tool description"):
        """Recursive: MCP nests descriptions per property inside inputSchema,
        and a poisoned property description reaches the model exactly like a
        top-level one."""
        out = []
        if isinstance(node, dict):
            if isinstance(node.get("description"), str):
                out.append((node["description"], where))
            for v in node.values():
                out.extend(self._descriptions(v, where))
        elif isinstance(node, list):
            for v in node:
                out.extend(self._descriptions(v, where))
        return out


class ToolDeclarationCheck(Check):
    id = "tool_declarations"
    title = "Declared tools versus authorization policy"
    limitations = (
        "Matches tool names in OpenAI/Anthropic-style function schemas found in source. It CANNOT "
        "see tools registered dynamically, names built by string concatenation, or frameworks "
        "whose schema shape it does not recognise. A tool it does not find is not a tool that "
        "does not exist."
    )

    # Tool capabilities that are destructive or high-consequence regardless
    # of what the surrounding application intends.
    #
    # Matched against TOKENS, not with word boundaries. `\bdelete\b` cannot
    # match inside `delete_everything`, because `_` is a word character --
    # so a word-boundary pattern misses snake_case, which is the dominant
    # convention for tool names. That defect was in the first version of
    # this check and `send_email` only matched by accident, via a literal
    # alternative in the pattern.
    _CONSEQUENTIAL_TOKENS = {
        "delete", "drop", "remove", "destroy", "truncate", "purge", "wipe",
        "exec", "execute", "shell", "command", "eval", "run", "spawn",
        "transfer", "payment", "pay", "refund", "wire", "charge",
        "sendmail", "email", "sms", "publish", "deploy",
        "write", "overwrite", "rm", "chmod", "sudo", "grant", "revoke",
    }

    _CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

    @classmethod
    def _tokens(cls, name: str) -> set[str]:
        """Splits a tool name on separators AND camelCase boundaries, so
        delete_everything, database.delete, deleteEverything and
        delete-all all yield the token 'delete'."""
        spaced = cls._CAMEL.sub(" ", name)
        return {t.lower() for t in re.split(r"[\s_\-.:/]+", spaced) if t}

    @classmethod
    def _is_consequential(cls, name: str) -> bool:
        return bool(cls._tokens(name) & cls._CONSEQUENTIAL_TOKENS)

    _NAME_IN_SCHEMA = re.compile(r'["\']name["\']\s*:\s*["\']([A-Za-z0-9_.\-]{2,64})["\']')

    def run(self, root: Path, files: list[Path]) -> CheckResult:
        from sentinelcore.services.tool_policy import authorize_tool, load_tool_policy

        result = CheckResult(check_id=self.id)
        policy = load_tool_policy()
        known = set(policy.get("tools", {}))
        seen: dict[str, tuple[str, int]] = {}

        for path in files:
            if path.suffix.lower() not in {".py", ".js", ".ts", ".json", ".yaml", ".yml"}:
                continue
            text = read_text(path)
            if text is None or "description" not in text:
                continue  # a function schema without a description is unlikely
            result.files_examined += 1
            rel = str(path.relative_to(root))
            for i, line in enumerate(text.splitlines(), 1):
                for m in self._NAME_IN_SCHEMA.finditer(line):
                    name = m.group(1)
                    if self._is_consequential(name) and name not in seen:
                        seen[name] = (rel, i)

        for name, (rel, line) in sorted(seen.items()):
            decision = authorize_tool(name, policy)
            if name in known:
                continue  # explicitly governed; the operator has decided
            result.findings.append(AssessmentFinding(
                check_id=self.id, severity=Severity.HIGH,
                title=f"Consequential tool '{name}' has no explicit authorization rule",
                detail=f"'{name}' looks capable of a destructive or high-consequence action and is "
                       f"not listed in tool_policy.yaml, so it falls to the default "
                       f"('{decision.value}').",
                remediation=f"Add an explicit rule for '{name}' in tool_policy.yaml -- 'block' or "
                            "'human_approval' for genuinely destructive actions. Relying on the "
                            "default means the decision was never made.",
                path=rel, line=line))
        return result


class SentinelCoreConfigCheck(Check):
    id = "sentinelcore_config"
    title = "SentinelCore's own configuration"
    limitations = (
        "Reads the configuration this process would load. It CANNOT see what a different "
        "deployment sets, so run it in the environment you intend to deploy."
    )

    def run(self, root: Path, files: list[Path]) -> CheckResult:
        from sentinelcore.core.auth import parse_api_keys
        from sentinelcore.core.config import settings

        result = CheckResult(check_id=self.id)
        add = result.findings.append

        if not parse_api_keys():
            add(AssessmentFinding(
                check_id=self.id, severity=Severity.HIGH,
                title="Authentication is disabled",
                detail="SENTINELCORE_API_KEYS is unset, so every endpoint -- including the audit "
                       "trail and the proxy -- is reachable without credentials.",
                remediation="Set SENTINELCORE_API_KEYS='key:role,...' before exposing the gateway "
                            "on a network. Acceptable only for local use."))

        if not settings.rate_limit_enabled:
            add(AssessmentFinding(
                check_id=self.id, severity=Severity.MEDIUM,
                title="Rate limiting is disabled",
                detail="Nothing bounds request volume. Scanning costs CPU and the proxy path costs "
                       "money at the upstream provider.",
                remediation="Set SENTINELCORE_RATE_LIMIT_ENABLED=true and size the limit per "
                            "worker process -- limits are per-process, not per-deployment."))

        if not settings.retention_enabled:
            add(AssessmentFinding(
                check_id=self.id, severity=Severity.MEDIUM,
                title="Audit retention is disabled",
                detail="The audit table grows without bound.",
                remediation="Enable retention, or accept unbounded growth deliberately and monitor "
                            "the table size."))

        if not settings.audit_enabled:
            add(AssessmentFinding(
                check_id=self.id, severity=Severity.HIGH,
                title="Audit logging is disabled",
                detail="Security decisions are made but never recorded, so an incident cannot be "
                       "investigated after the fact.",
                remediation="Set SENTINELCORE_AUDIT_ENABLED=true."))

        if settings.storage_backend == "sqlite" and settings.audit_db_path == ":memory:":
            add(AssessmentFinding(
                check_id=self.id, severity=Severity.HIGH,
                title="Audit database is in-memory",
                detail="Records are lost on restart.",
                remediation="Point SENTINELCORE_AUDIT_DB_PATH at a durable path."))

        if settings.semantic_detector_enabled:
            add(AssessmentFinding(
                check_id=self.id, severity=Severity.INFO,
                title="Semantic detector is enabled (third-party data egress)",
                detail="Scanned text is sent to an external API. The text being scanned may itself "
                       "contain the secrets and PII the scan is looking for.",
                remediation="Confirm this is acceptable for your data classification. The rules and "
                            "learned detectors run entirely locally."))

        return result


ALL_CHECKS: list[Check] = [
    SecretsCheck(), MCPDefinitionCheck(), ToolDeclarationCheck(), SentinelCoreConfigCheck(),
]
