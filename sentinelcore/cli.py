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
    parser = argparse.ArgumentParser(prog="sentinel", description="SentinelCore security control plane")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("doctor", help="check installation and configuration")

    pol = sub.add_parser("policy", help="inspect policy presets")
    pol.add_argument("action", choices=["list", "show"], nargs="?", default="list")
    pol.add_argument("name", nargs="?", default=None)

    s = sub.add_parser("scan", help="scan text or a file")
    s.add_argument("target", help="text to scan, or - to read stdin")
    s.add_argument("--policy", default="balanced", help="monitor | balanced | strict | maximum")
    s.add_argument("--origin", default="input")

    t = sub.add_parser("tool", help="check a tool call")
    t.add_argument("name")
    t.add_argument("--args", default="{}", help="JSON object of arguments")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 3

    if args.command == "doctor":
        return _doctor(args.json)

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
