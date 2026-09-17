"""Assessment runner and report rendering."""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelcore.assess.base import AssessmentFinding, Check, Severity, severity_rank, walk
from sentinelcore.assess.checks import ALL_CHECKS


@dataclass
class Assessment:
    root: str
    findings: list[AssessmentFinding] = field(default_factory=list)
    files_examined: int = 0
    duration_seconds: float = 0.0
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: dict[str, str] = field(default_factory=dict)
    suppressed: int = 0
    limitations: dict[str, str] = field(default_factory=dict)

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    def worst_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=severity_rank, default=None)

    def exit_code(self) -> int:
        """Contract for CI. A tool whose exit code does not distinguish
        'clean' from 'critical' cannot gate a pipeline."""
        w = self.worst_severity()
        if w is None or w == Severity.INFO:
            return 0
        if w in (Severity.LOW, Severity.MEDIUM):
            return 1
        return 2   # HIGH or CRITICAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_examined": self.files_examined,
            "duration_seconds": round(self.duration_seconds, 3),
            "checks_run": self.checks_run,
            "checks_skipped": self.checks_skipped,
            "summary": self.by_severity(),
            "suppressed_by_inline_ignore": self.suppressed,
            "worst_severity": self.worst_severity().value if self.worst_severity() else None,
            "exit_code": self.exit_code(),
            "findings": [f.to_dict() for f in self.findings],
            "limitations": self.limitations,
            "disclaimer": (
                "Static assessment of a configuration surface. It cannot see prompts assembled at "
                "runtime, tools registered dynamically, or MCP servers discovered over the network. "
                "A clean result means these specific checks found nothing, not that the application "
                "is secure."
            ),
        }


def assess(root: Path, checks: list[Check] | None = None) -> Assessment:
    checks = checks or ALL_CHECKS
    started = time.monotonic()
    files = list(walk(root))
    report = Assessment(root=str(root))

    for check in checks:
        report.limitations[check.id] = check.limitations
        try:
            result = check.run(root, files)
        except Exception as e:
            # One failing check must not abort the assessment -- a partial
            # report is useful; a crash tells the operator nothing.
            report.checks_skipped[check.id] = f"check raised {type(e).__name__}"
            continue
        report.checks_run.append(check.id)
        report.files_examined = max(report.files_examined, result.files_examined)
        if result.skipped:
            report.checks_skipped[check.id] = result.skipped
        report.suppressed += result.suppressed
        report.findings.extend(result.findings)

    report.findings.sort(key=lambda f: (-severity_rank(f.severity), f.check_id, f.path or ""))
    report.duration_seconds = time.monotonic() - started
    return report


_ICON = {Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH", Severity.MEDIUM: "MED ",
         Severity.LOW: "LOW ", Severity.INFO: "INFO"}


def render(report: Assessment, show_limitations: bool = True) -> str:
    lines = [f"SentinelCore pre-deployment assessment", f"  {report.root}",
             f"  {report.files_examined} files, {len(report.checks_run)} checks, "
             f"{report.duration_seconds:.2f}s", ""]

    if not report.findings:
        lines.append("  No findings from the checks that ran.")
    else:
        for f in report.findings:
            lines.append(f"  [{_ICON[f.severity]}] {f.title}")
            lines.append(f"         {f.location()}")
            lines.append(f"         {f.detail}")
            if f.evidence:
                lines.append(f"         evidence: {f.evidence}")
            lines.append(f"         fix: {f.remediation}")
            lines.append("")

    if report.suppressed:
        lines.append(f"  {report.suppressed} finding(s) suppressed by inline sentinel:ignore")
        lines.append("")

    counts = report.by_severity()
    if counts:
        lines.append("  " + "  ".join(f"{k}: {v}" for k, v in
                                      sorted(counts.items(), key=lambda kv: -severity_rank(Severity(kv[0])))))
        lines.append("")

    if report.checks_skipped:
        lines.append("  Checks that did not run:")
        for cid, why in report.checks_skipped.items():
            lines.append(f"    {cid}: {why}")
        lines.append("")

    if show_limitations:
        lines.append("  What this assessment CANNOT see:")
        for cid in report.checks_run:
            lines.append(f"    {cid}: {report.limitations[cid]}")
        lines.append("")
        lines.append("  A clean result means these checks found nothing -- not that the")
        lines.append("  application is secure. Runtime protection covers what static")
        lines.append("  analysis cannot.")

    return "\n".join(lines)
