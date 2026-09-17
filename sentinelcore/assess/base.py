"""
Pre-deployment assessment.

WHAT THIS IS
A static inspection of an AI application's *configuration surface* before
it ships: system prompts held in source, MCP server definitions, declared
tool schemas, hardcoded credentials, and SentinelCore's own settings.

WHAT THIS IS NOT, and the distinction matters
It is not a guarantee that an application is secure, and it cannot be.
Static analysis sees what is written down. It cannot see prompts assembled
at runtime, tools registered dynamically, MCP servers discovered over the
network, or any behaviour that depends on data. Every check below declares
its own blind spot in `limitations`, and the report prints them, because a
scanner that reports "0 issues" without saying what it never looked at
teaches the reader the wrong thing.

The honest framing: this raises *enumerable* classes of problem early. It
is a complement to the runtime gateway, not a substitute -- the gateway is
what sees the things static analysis cannot.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_ORDER = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}


@dataclass
class AssessmentFinding:
    check_id: str
    severity: Severity
    title: str
    detail: str
    remediation: str
    path: str | None = None
    line: int | None = None
    evidence: str | None = None      # ALWAYS redacted by the check that sets it

    def location(self) -> str:
        if not self.path:
            return "configuration"
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id, "severity": self.severity.value, "title": self.title,
            "detail": self.detail, "remediation": self.remediation,
            "path": self.path, "line": self.line, "evidence": self.evidence,
        }


@dataclass
class CheckResult:
    check_id: str
    findings: list[AssessmentFinding] = field(default_factory=list)
    files_examined: int = 0
    suppressed: int = 0              # findings excused by an inline sentinel:ignore
    skipped: str | None = None       # why the check could not run, if it could not


class Check(ABC):
    """One enumerable class of pre-deployment problem."""

    id: str
    title: str
    limitations: str   # required: what this check CANNOT see

    @abstractmethod
    def run(self, root: Path, files: list[Path]) -> CheckResult: ...


# Resource bounds. An assessment tool that can be made to exhaust memory by
# pointing it at a large repository is the same defect class already found
# twice in this project (unbounded limiter keys, unbounded alert queue).
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 20_000

# Directories never worth walking. Scanning a virtualenv finds thousands of
# "issues" in third-party code the developer did not write and cannot fix,
# which is how a security tool trains people to ignore it.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".tox",
    "site-packages", ".next", ".nuxt", "target", "vendor", ".terraform",
}

SOURCE_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java",
                   ".rs", ".php", ".cs", ".kt", ".swift", ".md", ".txt"}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".cfg"}


def walk(root: Path) -> Iterator[Path]:
    """Yields candidate files, bounded and filtered."""
    count = 0
    for path in sorted(root.rglob("*")):
        if count >= MAX_FILES:
            return
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES | CONFIG_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        yield path


def read_text(path: Path) -> str | None:
    """Binary files and undecodable content are skipped rather than
    guessed at -- a mojibake scan produces confident nonsense."""
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


# Inline suppression. A scanner with no way to say "I looked at this and
# it is fine" is a scanner people stop running -- but a suppression that
# lives outside the code is a suppression nobody reviews. An inline comment
# is visible in review, travels with the line it excuses, and shows up in a
# diff when the line changes.
#
# Deliberately NOT a config file of glob patterns: those accumulate silently
# and end up excluding whole directories that once had one false positive.
#
#   secret = "AKIA..."   # sentinel:ignore  -- fixture for the attack corpus
#   secret = "AKIA..."   # sentinel:ignore[secrets]
_IGNORE = re.compile(r"#\s*sentinel:ignore(?:\[([a-z_,\s]+)\])?", re.I)


def suppressed(line: str, check_id: str) -> bool:
    """Whether an inline comment excuses this check on this line."""
    m = _IGNORE.search(line)
    if not m:
        return False
    scoped = m.group(1)
    if not scoped:
        return True                       # bare ignore: all checks on this line
    return check_id in {s.strip() for s in scoped.split(",")}


def worst(findings: list[AssessmentFinding]) -> Severity | None:
    return max((f.severity for f in findings), key=lambda s: _ORDER[s], default=None)


def severity_rank(s: Severity) -> int:
    return _ORDER[s]
