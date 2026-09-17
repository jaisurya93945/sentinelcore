"""
Command-line interface.

Exit codes are part of the contract, because the main reason to have a CLI
is to put it in CI:

    0  clean
    1  findings present but nothing blocking
    2  blocking decision reached
    3  usage or configuration error
"""

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    # --json is accepted BOTH before and after the subcommand. Requiring it
    # before ("sentinel --json assess .") is unlike every other CLI a
    # developer uses, and "sentinel assess . --json" failing with a bare
    # argparse error is a bad first impression for a security tool.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")

    parser = argparse.ArgumentParser(prog="sentinel", parents=[common],
                                     description="SentinelCore security control plane")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("doctor", help="check installation and configuration", parents=[common])

    ass = sub.add_parser("assess", parents=[common], help="pre-deployment assessment of a codebase")
    ass.add_argument("path", nargs="?", default=".")
    ass.add_argument("--no-limitations", action="store_true",
                     help="omit the 'what this cannot see' section (not recommended)")

    exp = sub.add_parser("export-feedback", parents=[common], help="export operator-reported false positives as benchmark cases")
    exp.add_argument("--out", default="hard_negatives.jsonl")

    pol = sub.add_parser("policy", parents=[common], help="inspect policy presets")
    pol.add_argument("action", choices=["list", "show"], nargs="?", default="list")
    pol.add_argument("name", nargs="?", default=None)

    s = sub.add_parser("scan", parents=[common], help="scan text or a file")
    s.add_argument("target", help="text to scan, or - to read stdin")
    s.add_argument("--policy", default="balanced", help="monitor | balanced | strict | maximum")
    s.add_argument("--origin", default="input")

    t = sub.add_parser("tool", parents=[common], help="check a tool call")
    t.add_argument("name")
    t.add_argument("--args", default="{}", help="JSON object of arguments")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 3

    if args.command == "doctor":
        return _doctor(args.json)

    if args.command == "assess":
        from pathlib import Path

        from sentinelcore.assess.runner import assess, render

        root = Path(args.path).resolve()
        if not root.exists():
            print(f"error: {root} does not exist", file=sys.stderr)
            return 3
        report = assess(root)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(render(report, show_limitations=not args.no_limitations))
        return report.exit_code()

    if args.command == "export-feedback":
        from sentinelcore.services.feedback import export_hard_negatives, list_feedback, Verdict

        total_fp = len(list_feedback(Verdict.FALSE_POSITIVE, limit=10000))
        n = export_hard_negatives(args.out)
        skipped = total_fp - n
        print(f"exported {n} hard negatives to {args.out}")
        if skipped:
            print(f"skipped {skipped} false-positive report(s) with no supplied text "
                  f"(a case with no text cannot be replayed)")
        return 0 if n else 1

    if args.command == "policy":
        from sentinelcore import presets

        if args.action == "show" and args.name:
            try:
                pr = presets.get(args.name)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 3
            if args.json:
                print(json.dumps(pr.__dict__, indent=2, default=str))
            else:
                print(f"{pr.name}\n\n  {pr.description}\n")
                print(f"  measured as: {pr.ablation_config}")
                print(f"  APR: {pr.apr:.1%} [{pr.apr_ci[0]:.1%}-{pr.apr_ci[1]:.1%}]")
                print(f"  BCR: {pr.bcr:.1%} [{pr.bcr_ci[0]:.1%}-{pr.bcr_ci[1]:.1%}]\n")
                print(f"  trade-off: {pr.trade_off}")
            return 0
        if args.json:
            print(json.dumps({k: v.__dict__ for k, v in presets.PRESETS.items()}, indent=2, default=str))
        else:
            print(presets.compare())
        return 0

    from sentinelcore import Guard

    try:
        guard = Guard(policy=getattr(args, "policy", "balanced"))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if args.command == "scan":
        text = sys.stdin.read() if args.target == "-" else args.target
        outcome = guard.scan(text, origin=args.origin)
    else:
        try:
            outcome = guard.check_tool_call(args.name, json.loads(args.args))
        except json.JSONDecodeError as e:
            print(f"error: --args must be valid JSON ({e})", file=sys.stderr)
            return 3

    if args.json:
        print(json.dumps(outcome.to_dict(), indent=2))
    else:
        print(f"decision:   {outcome.decision.value}")
        print(f"risk score: {outcome.risk_score}")
        if outcome.sanitized_text is not None:
            print(f"sanitized:  {outcome.sanitized_text!r}")
        for f in outcome.findings:
            print(f"  - {f.type} ({f.severity.value}) from {f.origin}")
        if not outcome.findings:
            print("  no findings")

    if not outcome.allowed:
        return 2
    return 1 if outcome.findings else 0


def _doctor(as_json: bool) -> int:
    import importlib

    checks = {}
    for name, mod, extra in [
        ("core", "sentinelcore.guard", None),
        ("server (fastapi)", "fastapi", "server"),
        ("learned detector (sklearn)", "sklearn", "ml"),
        ("semantic detector (openai)", "openai", "semantic"),
    ]:
        try:
            importlib.import_module(mod)
            checks[name] = {"ok": True, "extra": extra}
        except ImportError:
            checks[name] = {"ok": False, "extra": extra}

    from sentinelcore import __version__
    from sentinelcore.detectors.registry import get_registered_detectors

    detectors = sorted(get_registered_detectors())

    if as_json:
        print(json.dumps({"version": __version__, "checks": checks, "detectors": detectors}, indent=2))
    else:
        print(f"sentinelcore {__version__}\n")
        for name, c in checks.items():
            mark = "ok " if c["ok"] else "-- "
            hint = "" if c["ok"] or not c["extra"] else f"   (pip install 'sentinelcore[{c['extra']}]')"
            print(f"  [{mark}] {name}{hint}")
        print(f"\n  registered detectors: {', '.join(detectors)}")
        if not checks["core"]["ok"]:
            print("\n  core import failed -- installation is broken")
    return 0 if checks["core"]["ok"] else 3


if __name__ == "__main__":
    sys.exit(main())
