"""
Guards against documentation drifting from measured results.

This project has now had documentation silently contradict its own result
files four separate times: a v1 ablation table left sitting above the v2
table, a hardening status still reading DECLINED months after the work
shipped, ablation thresholds duplicated from the detector and drifted
apart, and retracted figures left in the paper. Every instance was caught
by manual grepping, which is not a control.

These tests are cheap and load-bearing: they read the actual result JSON
and assert the headline numbers appear in the paper. They will fail when
an experiment is re-run and the paper is not updated -- which is exactly
the failure mode.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
PAPER = ROOT / "docs" / "paper" / "DRAFT.md"
PROCESSED = ROOT / "dataset" / "processed"


def _needs(path: Path):
    if not path.exists():
        pytest.skip(f"{path.name} not generated; run the corresponding script")
    return json.loads(path.read_text())


def test_paper_exists():
    assert PAPER.exists()


def test_paper_matches_ablation_headline_numbers():
    ab = _needs(PROCESSED / "ablation_results_v2.json")["summary"]
    text = PAPER.read_text()
    for cfg in ("A_content_only", "J_ml_flat", "K_ml_prov"):
        apr = f"{ab[cfg]['attack_prevention_rate']:.3f}"
        assert apr in text, f"paper is missing current APR {apr} for {cfg} -- re-sync docs/paper/DRAFT.md"


def test_paper_matches_bootstrap_intervals():
    st = _needs(PROCESSED / "statistical_validation.json")
    text = PAPER.read_text()
    j = st["agent_bootstrap"]["J_ml_flat"]["APR"]
    assert f"{j['ci95_low']:.3f}" in text and f"{j['ci95_high']:.3f}" in text, (
        "paper's J confidence interval does not match statistical_validation.json"
    )


def test_paper_does_not_contain_retracted_claims():
    """Specific figures this project has formally withdrawn. If a future
    edit reintroduces one, that is a regression, not a rewording."""
    text = PAPER.read_text()
    retracted = [
        ("4.84×", "superseded recall-improvement figure"),
        ("+9.1 points at zero utility cost", "v1 oracle claim, superseded by v2"),
    ]
    for needle, why in retracted:
        assert needle not in text, f"retracted claim reintroduced ({why}): {needle}"


def test_shipped_thresholds_match_documented_values():
    """The ablation previously duplicated these and silently drifted."""
    from app.detectors.ml_classifier.detector import HIGH_CONFIDENCE, REPORTING_FLOOR

    assert REPORTING_FLOOR == 0.50
    assert HIGH_CONFIDENCE == 0.80
    text = PAPER.read_text()
    assert "0.50" in text and "0.80" in text


def test_ablation_imports_thresholds_rather_than_duplicating():
    src = (ROOT / "scripts" / "run_ablation.py").read_text()
    assert "from app.detectors.ml_classifier.detector import" in src, (
        "run_ablation.py must import shipped thresholds, not redefine them"
    )
    assert not re.search(r"p\s*<\s*0\.35", src), "hardcoded threshold reintroduced in run_ablation.py"
