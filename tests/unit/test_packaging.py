"""
Packaging integrity.

These exist because a real defect nearly shipped: a shell operator-
precedence mistake unzipped the repository into itself, creating
`sentinelcore/sentinelcore/` -- a complete nested duplicate. It was
untracked, so `git status` looked fine, but it was already inside the
built wheel and a routine `git add -A` would have committed it.

PyPI versions are immutable. A packaging defect that reaches the index
cannot be replaced, only yanked. These checks are cheap and the failure
they prevent is permanent.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
PKG = ROOT / "sentinelcore"


def test_no_nested_package_directory():
    """The exact defect that nearly shipped."""
    assert not (PKG / "sentinelcore").exists(), (
        "sentinelcore/sentinelcore/ exists -- the repository was unpacked into itself. "
        "This would ship a duplicate of the whole project inside the wheel."
    )


def test_package_contains_no_repository_scaffolding():
    """Only package code belongs under the import root. Tests, docs,
    datasets and CI config inside it bloat the wheel and can shadow the
    user's own modules."""
    stray = [n for n in ("tests", "docs", "scripts", "dataset", ".github", "Dockerfile",
                         "pyproject.toml", ".git", ".gitignore", "README.md")
             if (PKG / n).exists()]
    assert not stray, f"repository scaffolding leaked into the package: {stray}"


def test_required_data_files_are_present():
    """Silent-failure class: these are loaded at runtime, so a missing
    entry in package-data produces a broken install rather than a build
    error."""
    for rel in ("services/policy.yaml", "services/tool_policy.yaml", "static/dashboard.html", "py.typed"):
        assert (PKG / rel).exists(), f"{rel} missing -- an installed wheel would fail at runtime"


def test_package_data_declaration_covers_every_non_python_file():
    """Guards the inverse: a new YAML added to services/ that nobody lists
    in pyproject.toml works in development and breaks only once installed."""
    import tomllib

    cfg = tomllib.load(open(ROOT / "pyproject.toml", "rb"))
    patterns = cfg["tool"]["setuptools"]["package-data"]["sentinelcore"]

    import fnmatch

    uncovered = []
    for f in PKG.rglob("*"):
        if f.is_dir() or f.suffix == ".py":
            continue
        # Dot-directories are never packaged by setuptools; excluding them
        # here keeps this test about package-data coverage. A stray .git
        # inside the package is caught by the scaffolding test above, which
        # is where that belongs.
        if any(part.startswith(".") or part == "__pycache__" for part in f.parts):
            continue
        rel = f.relative_to(PKG).as_posix()
        if not any(fnmatch.fnmatch(rel, p) for p in patterns):
            uncovered.append(rel)
    assert not uncovered, f"non-Python files not covered by package-data: {uncovered}"


def test_version_is_consistent_between_package_and_pyproject():
    """A mismatch means the wheel says one thing and the code another; the
    release workflow refuses to publish on it, so catch it earlier."""
    import tomllib

    import sentinelcore

    declared = tomllib.load(open(ROOT / "pyproject.toml", "rb"))["project"]["version"]
    assert sentinelcore.__version__ == declared, (
        f"sentinelcore.__version__ is {sentinelcore.__version__} but pyproject says {declared}"
    )


def test_core_dependencies_stay_minimal():
    """A security library that drags in a web framework and a numeric stack
    by default is one most people cannot adopt. Heavy deps belong in extras."""
    import tomllib

    deps = tomllib.load(open(ROOT / "pyproject.toml", "rb"))["project"]["dependencies"]
    names = {d.split(">")[0].split("=")[0].split("[")[0].strip().lower() for d in deps}
    for heavy in ("fastapi", "uvicorn", "scikit-learn", "torch", "transformers", "openai", "httpx"):
        assert heavy not in names, f"{heavy} must be an optional extra, not a core dependency"
