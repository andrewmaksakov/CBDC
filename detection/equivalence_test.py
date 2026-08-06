"""TOST equivalence test: pseudonymous linkage (T2) vs full surveillance (T4).

The paper's thesis is "identity + watchlist add no meaningful detection
value beyond ZK-achievable pseudonymous linkage." That is an EQUIVALENCE
claim, so it needs an equivalence test with a pre-registered margin, not
"1.00 = 1.00" on a saturated toy.

Method: paired entity-clustered percentile bootstrap of
    dAUC = AUC(T4) - AUC(T2)
using the same resampled entities for both tiers (per-entity out-of-fold
scores from detection_experiment.py). Two one-sided tests at level alpha
== the (1 - 2*alpha) percentile CI lying inside (-delta, +delta).

Verdicts — the harness must be able to produce ALL of these:
  EQUIVALENT               CI entirely inside (-delta, +delta): thesis holds.
  SURVEILLANCE_SUPERIOR    CI lower bound > +delta: identity/watchlist beat
                           linkage beyond the margin — THESIS FALSIFIED.
  LINKAGE_SUPERIOR         CI upper bound < -delta (would be odd; flags a
                           harness or DGP problem worth investigating).
  INCONCLUSIVE             CI straddles a margin bound: underpowered; no
                           equivalence claim may be made.

Default margin delta = 0.03 AUC (design pack §8 Q2 — pre-registered
default, an open call for MF; must be fixed before real-data runs).

METRIC DEPENDENCE (added 24 Jul 2026 — POST HOC, disclose as such).
The test was originally AUC-only. At the operating points this DGP
produces, AUC saturates: every tier sits above 0.98 once the study is
adequately powered, so "equivalence within 0.03 AUC" is close to
unfalsifiable and the verdict carries little information. Average
precision does not saturate at ~5% prevalence, and it is the quantity a
deployment actually operates on when allocating a fixed alert budget.
The two metrics can disagree — at n=8000 the logistic model returns
EQUIVALENT on AUC and SURVEILLANCE_SUPERIOR on AP — so a verdict is only
meaningful when reported WITH its metric.

Because delta was chosen for AUC before any AP result existed, applying
the same 0.03 to AP would be a post hoc margin choice on a different
scale (AP baseline = prevalence ~0.05; AUC baseline = 0.5). We therefore
also return `equiv_bound`: the smallest margin at which this comparison
WOULD be declared equivalent, i.e. max(|ci_lo|, |ci_hi|). Reporting that
bound lets a reader apply their own margin and is immune to the
objection that the margin was selected after seeing the data. Prefer it
to the verdict when writing up AP.
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

DELTA_DEFAULT = 0.03
ALPHA = 0.05
N_BOOT = 2000

METRICS = {"auc": roc_auc_score, "ap": average_precision_score}


def tost_equivalence(oof, tier_lo="T2", tier_hi="T4", model="gboost",
                     delta=DELTA_DEFAULT, alpha=ALPHA, n_boot=N_BOOT,
                     seed=0, metric="auc") -> dict:
    if metric not in METRICS:
        raise ValueError(f"metric must be one of {sorted(METRICS)}")
    score = METRICS[metric]

    y = oof.is_launderer.to_numpy()
    s_lo = oof[f"{tier_lo}_{model}"].to_numpy()
    s_hi = oof[f"{tier_hi}_{model}"].to_numpy()
    d_point = score(y, s_hi) - score(y, s_lo)

    rng = np.random.default_rng(seed)
    n = len(y)
    deltas = []
    while len(deltas) < n_boot:
        idx = rng.integers(0, n, n)          # same entities for both tiers
        if y[idx].min() == y[idx].max():
            continue
        deltas.append(score(y[idx], s_hi[idx]) - score(y[idx], s_lo[idx]))
    deltas = np.asarray(deltas)
    ci_lo, ci_hi = np.percentile(deltas, [100 * alpha, 100 * (1 - alpha)])

    if ci_lo > delta:
        verdict = "SURVEILLANCE_SUPERIOR"    # thesis falsified
    elif ci_hi < -delta:
        verdict = "LINKAGE_SUPERIOR"
    elif -delta < ci_lo and ci_hi < delta:
        verdict = "EQUIVALENT"
    else:
        verdict = "INCONCLUSIVE"

    out = {
        "comparison": f"{tier_hi} vs {tier_lo} ({model})",
        "metric": metric,
        "delta_margin": delta,
        "alpha": alpha,
        "n_boot": n_boot,
        "n_entities": int(n),
        "n_launderers": int(y.sum()),
        "d_point": float(d_point),
        "d_ci90": [float(ci_lo), float(ci_hi)],
        # Smallest margin at which this comparison would read EQUIVALENT.
        # Margin-free; report this rather than the verdict for AP.
        "equiv_bound": float(max(abs(ci_lo), abs(ci_hi))),
        "boot_frac_above_margin": float((deltas > delta).mean()),
        "boot_frac_below_neg_margin": float((deltas < -delta).mean()),
        "verdict": verdict,
    }
    if metric == "auc":            # back-compat with the pre-24-Jul schema
        out["dAUC_point"] = float(d_point)
        out["dAUC_ci90"] = [float(ci_lo), float(ci_hi)]
    return out


def print_tost(res):
    m = res.get("metric", "auc").upper()
    print(f"TOST {res['comparison']}: d{m} = {res['d_point']:+.4f}, "
          f"90% CI [{res['d_ci90'][0]:+.4f}, {res['d_ci90'][1]:+.4f}], "
          f"margin ±{res['delta_margin']}")
    print(f"  effective N = {res['n_entities']} entities "
          f"({res['n_launderers']} launderers)")
    print(f"  equivalence bound: ±{res['equiv_bound']:.4f} "
          f"(smallest margin giving EQUIVALENT)")
    print(f"  verdict [{m}]: {res['verdict']}")
