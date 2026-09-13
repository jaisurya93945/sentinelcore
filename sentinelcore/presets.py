"""
Named policy presets, each carrying its MEASURED operating point.

WHY THESE EXIST
The most useful thing this project measured is not a detector score; it is
the shape of the security/utility frontier. A preset is how that reaches a
developer who will never read an ablation table.

WHY EACH ONE CITES A NUMBER
A preset named "strict" with no measurement behind it is a guess wearing a
label. Every preset below corresponds to a configuration that was actually
run (`scripts/run_ablation.py`), and reports the attack-prevention and
benign-completion rates observed for it, with bootstrap confidence
intervals.

HOW TO READ THE NUMBERS -- and they are NOT a guarantee
  APR  attack prevention rate: attack traces whose unsafe action was
       stopped. WARN is excluded -- a warning stops nothing.
  BCR  benign completion rate: benign traces allowed to finish. This is
       the cost axis. A configuration that blocks everything scores APR
       1.00 and is useless.

They come from 85 attack / 85 benign traces on OUR agent-trace benchmark,
whose payload text is externally authored but whose structure is ours.
They describe behaviour on that benchmark, not on your traffic. Treat them
as a calibrated starting point and re-measure against your own data --
`scripts/run_ablation.py` accepts a different trace file.

KNOWN AND STATED: over-defense against benign text containing attack
vocabulary is UNMEASURED (5/399 hard negatives in the corpus; see
docs/research/README.md Finding 10). The BCR figures below are therefore
optimistic for deployments whose users legitimately discuss security.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Preset:
    name: str
    description: str
    ablation_config: str
    apr: float
    apr_ci: tuple[float, float]
    bcr: float
    bcr_ci: tuple[float, float]
    tool_authorization: bool
    provenance_rules: bool
    sanitize: bool
    requires_ml: bool
    trade_off: str

    def summary(self) -> str:
        return (
            f"{self.name}: APR {self.apr:.1%} [{self.apr_ci[0]:.1%}-{self.apr_ci[1]:.1%}], "
            f"BCR {self.bcr:.1%} [{self.bcr_ci[0]:.1%}-{self.bcr_ci[1]:.1%}] "
            f"(measured as {self.ablation_config})"
        )


PRESETS: dict[str, Preset] = {
    "monitor": Preset(
        name="monitor",
        description=(
            "Detection and reporting only. No tool authorization, no provenance "
            "escalation. Nothing legitimate is ever blocked."
        ),
        ablation_config="A_content_only",
        apr=0.282, apr_ci=(0.188, 0.377),
        bcr=1.000, bcr_ci=(1.000, 1.000),
        tool_authorization=False, provenance_rules=False, sanitize=False, requires_ml=False,
        trade_off="Zero utility cost, and stops roughly one attack in four. Correct for a first deployment where you need to see traffic before enforcing on it.",
    ),
    "balanced": Preset(
        name="balanced",
        description=(
            "Adds deterministic tool authorization and provenance-conditioned policy. "
            "Runs entirely on local rules -- no ML dependency, no network call."
        ),
        ablation_config="E_prov_rules",
        apr=0.400, apr_ci=(0.294, 0.506),
        bcr=0.988, bcr_ci=(0.965, 1.000),
        tool_authorization=True, provenance_rules=True, sanitize=True, requires_ml=False,
        trade_off="1.2 points of benign completion buys 12 points of attack prevention, and the gain is concentrated in privileged actions with clean-looking arguments -- the class content scanning cannot see at all.",
    ),
    "strict": Preset(
        name="strict",
        description=(
            "Adds the learned detector. Requires sentinelcore[ml] and a trained model."
        ),
        ablation_config="J_ml_flat",
        apr=0.788, apr_ci=(0.694, 0.871),
        bcr=0.918, bcr_ci=(0.859, 0.977),
        tool_authorization=True, provenance_rules=False, sanitize=True, requires_ml=True,
        trade_off="The largest single improvement available: detector quality, not policy. Costs about 8 points of benign completion.",
    ),
    "maximum": Preset(
        name="maximum",
        description=(
            "Learned detector plus provenance escalation. The highest attack "
            "prevention measured, and the highest utility cost."
        ),
        ablation_config="K_ml_prov",
        apr=0.906, apr_ci=(0.835, 0.965),
        bcr=0.847, bcr_ci=(0.765, 0.918),
        tool_authorization=True, provenance_rules=True, sanitize=True, requires_ml=True,
        trade_off="Roughly one benign workflow in six is blocked. Justified only where a missed attack costs far more than an interrupted user -- and the APR gain over 'strict' has overlapping confidence intervals, so it is not a clearly separated improvement.",
    ),
}

DEFAULT = "balanced"


def get(name: str) -> Preset:
    if name not in PRESETS:
        raise ValueError(f"unknown preset {name!r}; expected one of {sorted(PRESETS)}")
    return PRESETS[name]


def compare() -> str:
    """The frontier, as a table. Used by `sentinel policy list`."""
    lines = [f"{'preset':<11}{'APR':>20}{'BCR':>20}   requires", "-" * 72]
    for p in PRESETS.values():
        apr = f"{p.apr:.1%} [{p.apr_ci[0]:.0%}-{p.apr_ci[1]:.0%}]"
        bcr = f"{p.bcr:.1%} [{p.bcr_ci[0]:.0%}-{p.bcr_ci[1]:.0%}]"
        req = "sentinelcore[ml]" if p.requires_ml else "core only"
        lines.append(f"{p.name:<11}{apr:>20}{bcr:>20}   {req}")
    lines.append("")
    lines.append("APR = attack prevention rate, BCR = benign completion rate.")
    lines.append("Measured on 85/85 agent traces (scripts/run_ablation.py). Not a guarantee;")
    lines.append("re-measure on your own traffic. Over-defense is UNMEASURED -- see Finding 10.")
    return "\n".join(lines)
