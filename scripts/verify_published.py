"""
Verify a PUBLISHED distribution, from an index, in isolation.

WHY THIS IS A SCRIPT AND NOT THREE LINES IN A README

The three lines in the README were wrong, and wrong in the direction that
reports success. They were:

    python -m venv /tmp/verify && /tmp/verify/bin/pip install ... sentinelcore-ai
    /tmp/verify/bin/python -c "import sentinelcore; print(sentinelcore.__version__)"

Run from a clone of this repository -- the obvious place to run them --
`python -c` puts the current directory first on sys.path, so `import
sentinelcore` resolves to ./sentinelcore/ in the working tree and never
touches the venv at all. An empty virtualenv "passes" that check. A
published wheel missing every data file would pass it too, because the
local source tree is intact and that is what got imported.

The point of verifying a published artifact is to test THE ARTIFACT. So
this script:

  1. builds the virtualenv outside the repository,
  2. runs every check with cwd set to that temp directory AND with -P,
     which stops Python prepending the script's directory to sys.path,
  3. asserts the imported module's __file__ is inside the virtualenv --
     the check that makes shadowing impossible rather than merely unlikely,
  4. asserts the version matches what pyproject declares,
  5. exercises the console script, which is installed metadata rather than
     importable code and so fails differently.

PyPI versions are immutable. A verification that cannot fail is worth less
than no verification, because it is trusted.

Usage:
    python scripts/verify_published.py --index testpypi
    python scripts/verify_published.py --index pypi
    python scripts/verify_published.py --index pypi --version 0.4.1
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent

INDEXES = {
    # TestPyPI does not mirror pydantic and friends, so an extra index is
    # required or the install fails on dependencies and looks like a defect
    # in this package.
    "testpypi": ["--index-url", "https://test.pypi.org/simple/",
                 "--extra-index-url", "https://pypi.org/simple/"],
    "pypi": [],
    # The wheel in ./dist, before it is uploaded anywhere. PyPI versions are
    # immutable, so a packaging defect found here costs nothing and the same
    # defect found after upload costs a version number permanently. It also
    # lets you confirm this script can actually fail, on an artifact you
    # control, rather than trusting it first on a release.
    "local": ["--find-links", str(ROOT / "dist")],
}


def _pyproject() -> dict:
    return tomllib.load(open(ROOT / "pyproject.toml", "rb"))["project"]


def _run(cmd, cwd, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        print(f"\n  command failed: {' '.join(str(c) for c in cmd)}")
        print((r.stdout + r.stderr).strip()[-1500:])
    return r


def _ensure_local_dist(dist: str, want: str, workdir: Path) -> bool:
    """Build ./dist if it does not already hold this version.

    Built in a throwaway virtualenv with `-P`, and neither of those is
    incidental. `python -m build` run from the project root fails outright
    once a ./build/ directory exists, because the working directory comes
    first on sys.path and `build` resolves to that directory instead of the
    installed package:

        No module named build.__main__; 'build' is a package and
        cannot be directly executed

    That is the same shadowing this whole script exists to defeat, showing
    up in the tooling rather than the check. `-P` drops the working
    directory from sys.path and it resolves correctly. The separate
    virtualenv keeps the build backend out of the environment we are about
    to verify, which must contain only what the wheel pulls in.
    """
    pattern = f"{dist.replace('-', '_')}-{want}-*.whl"
    if list((ROOT / "dist").glob(pattern)):
        return True

    print(f"      no {pattern} in ./dist — building it")
    bvenv = workdir / "buildenv"
    bpy = bvenv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    _run([sys.executable, "-m", "venv", str(bvenv)], cwd=workdir)
    r = _run([str(bpy), "-m", "pip", "install", "--quiet", "build"], cwd=workdir, check=False)
    if r.returncode != 0:
        print(f"      could not install the build backend:\n{(r.stdout + r.stderr).strip()[-600:]}")
        return False
    r = _run([str(bpy), "-P", "-m", "build", "--outdir", str(ROOT / "dist"), str(ROOT)],
             cwd=workdir, check=False)
    if r.returncode != 0:
        print(f"      build failed:\n{(r.stdout + r.stderr).strip()[-900:]}")
        return False
    return bool(list((ROOT / "dist").glob(pattern)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", choices=sorted(INDEXES), required=True)
    ap.add_argument("--dist", default=None, help="default: project.name from pyproject.toml")
    ap.add_argument("--version", default=None, help="default: project.version from pyproject.toml")
    ap.add_argument("--keep", action="store_true", help="do not delete the virtualenv")
    args = ap.parse_args()

    cfg = _pyproject()
    dist = args.dist or cfg["name"]
    want = args.version or cfg["version"]

    # Outside the repository, always. Building it in-tree would reintroduce
    # the exact shadowing this script exists to prevent.
    tmp = Path(tempfile.mkdtemp(prefix="verify-published-"))
    venv = tmp / "venv"
    py = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

    print(f"distribution : {dist}=={want}")
    print(f"index        : {args.index}")
    print(f"sandbox      : {tmp}\n")

    failures = []
    try:
        _run([sys.executable, "-m", "venv", str(venv)], cwd=tmp)

        print("[1/5] installing from the index")
        if args.index == "local" and not _ensure_local_dist(dist, want, tmp):
            print("      cannot verify: no local artifact to check")
            return 1
        r = _run([str(py), "-m", "pip", "install", "--quiet",
                  *INDEXES[args.index], f"{dist}=={want}"], cwd=tmp, check=False)
        if r.returncode != 0:
            out = (r.stdout + r.stderr)
            if "no matching distribution" in out.lower() or "from versions: none" in out.lower():
                print(f"      NOT PUBLISHED: {dist}=={want} is not on {args.index}.")
                print("      Nothing was uploaded, or the upload went to the other index.")
            else:
                print(f"      install failed:\n{out.strip()[-1200:]}")
            return 1
        print("      ok")

        # Every check below runs with cwd=tmp and -P. Either alone would be
        # enough; both are here because this is the one property the whole
        # script depends on.
        print("[2/5] the import resolves INSIDE the virtualenv, not a source tree")
        r = _run([str(py), "-P", "-c",
                  "import sentinelcore,json;"
                  "print(json.dumps({'file':sentinelcore.__file__,"
                  "'version':sentinelcore.__version__}))"], cwd=tmp, check=False)
        if r.returncode != 0:
            print(f"      import failed:\n{(r.stdout + r.stderr).strip()[-1200:]}")
            return 1
        info = json.loads(r.stdout.strip().splitlines()[-1])
        where = Path(info["file"]).resolve()
        if venv.resolve() not in where.parents:
            failures.append(f"imported {where}, which is outside {venv} -- "
                            f"this check was shadowed and proves nothing")
            print(f"      SHADOWED: {where}")
        else:
            print(f"      ok  ({where.relative_to(venv.resolve())})")

        print("[3/5] the installed version is the one expected")
        if info["version"] != want:
            failures.append(f"installed package reports {info['version']}, expected {want}")
            print(f"      MISMATCH: {info['version']} != {want}")
        else:
            print(f"      ok  ({info['version']})")

        print("[4/5] package data survived the build (runtime-loaded files)")
        r = _run([str(py), "-P", "-c",
                  "import sentinelcore,pathlib;"
                  "p=pathlib.Path(sentinelcore.__file__).parent;"
                  "missing=[f for f in ('services/policy.yaml','services/tool_policy.yaml',"
                  "'static/dashboard.html','py.typed') if not (p/f).exists()];"
                  "print('MISSING:'+','.join(missing) if missing else 'ok')"],
                 cwd=tmp, check=False)
        line = (r.stdout or "").strip().splitlines()[-1] if r.stdout.strip() else "no output"
        if line != "ok":
            failures.append(f"package data absent from the published wheel: {line}")
            print(f"      {line}")
        else:
            print("      ok")

        print("[5/5] the console script works")
        exe = venv / ("Scripts/sentinel.exe" if sys.platform == "win32" else "bin/sentinel")
        if not exe.exists():
            failures.append("the `sentinel` console script was not installed")
            print("      MISSING")
        else:
            r = _run([str(exe), "doctor"], cwd=tmp, check=False)
            if r.returncode != 0:
                failures.append(f"`sentinel doctor` exited {r.returncode}")
                print(f"      failed:\n{(r.stdout + r.stderr).strip()[-600:]}")
            else:
                print("      ok")
    finally:
        if args.keep:
            print(f"\nvirtualenv kept at {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED -- {dist}=={want} installs and works from {args.index}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
