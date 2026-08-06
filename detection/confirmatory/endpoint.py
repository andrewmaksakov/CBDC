"""Operational endpoint: missed illicit entities at a fixed alert budget.

Implements protocol v3 sections 3.2-3.4. Pure functions, no I/O, no model
code -- everything here is about turning a score vector into the quantity the
confirmatory analysis actually tests.

Why this replaces AUC/AP as the primary endpoint: ranking metrics answer "is
the ordering good", which is not the question a monitoring regime faces. A
regime reviews k cases and misses the rest. The endpoint below is the number
of illicit entities that go unreviewed, which is the quantity a tolerance can
be argued about in workload terms.

    MissedPer10k(T) = 10000 * (N_pos - TP_T) / n

CEILING WARNING. This endpoint saturates from the other side to AUC. If k is
small enough that every arm achieves precision 1.0 in the top k, then TP is
k for all tiers and Delta is identically zero -- not "small", zero, with no
sampling variation to detect. A non-inferiority test then returns PASS by
construction. Check `resolution_scan` before freezing k; a budget in the
saturated regime produces a verdict that was never at risk of coming out
otherwise, which is the same defect as the AUC=1.000 artifact this pipeline
exists to retract.
"""

from __future__ import annotations

import numpy as np

__all__ = [
    "budget_for",
    "select_alerts",
    "missed_per_10k",
    "true_positives",
    "delta_miss",
    "did",
    "resolution_scan",
]


def budget_for(k_star: int, n: int) -> int:
    """Alerts available on a population of size n, from a rate per 10,000.

    Protocol 3.2: k = k_star * n / 10000. Rounded to nearest, floored at 1 so
    a budget never silently becomes zero on a small population.
    """
    if k_star <= 0:
        raise ValueError("k_star must be positive")
    return max(1, int(round(k_star * n / 10_000)))


def select_alerts(scores, tiebreak, k: int) -> np.ndarray:
    """Indices of the k highest-scoring entities.

    Ties broken by LOWER tiebreak key winning (protocol 3.2). `tiebreak` must
    be numeric -- entity ids like "E10"/"E2" sort wrongly as strings, and a
    tie-break that depends on string collation is not reproducible across
    locales.
    """
    scores = np.asarray(scores, dtype=float)
    tiebreak = np.asarray(tiebreak)
    if scores.shape != tiebreak.shape:
        raise ValueError("scores and tiebreak must be the same length")
    if not np.issubdtype(tiebreak.dtype, np.number):
        raise TypeError("tiebreak must be numeric, not string entity ids")
    if k > len(scores):
        raise ValueError(f"budget k={k} exceeds population n={len(scores)}")
    # lexsort applies the LAST key first: primary = -score, secondary = id
    return np.lexsort((tiebreak, -scores))[:k]


def true_positives(y, scores, tiebreak, k: int) -> int:
    """Illicit entities inside the reviewed set."""
    y = np.asarray(y)
    return int(y[select_alerts(scores, tiebreak, k)].sum())


def missed_per_10k(y, scores, tiebreak, k: int) -> float:
    """Illicit entities NOT reviewed, scaled per 10,000 monitored.

    At n = 10,000 this is just (N_pos - TP); the scaling exists so replicates
    at other population sizes stay comparable.
    """
    y = np.asarray(y)
    n = len(y)
    n_pos = int(y.sum())
    tp = true_positives(y, scores, tiebreak, k)
    return 10_000.0 * (n_pos - tp) / n


def delta_miss(y, scores_lo, scores_hi, tiebreak, k: int) -> float:
    """Paired contrast, protocol 3.4.

        delta = MissedPer10k(lo) - MissedPer10k(hi)

    With lo=T2 and hi=T4: POSITIVE means T2 misses MORE illicit entities than
    T4, i.e. withholding the auxiliary block costs detection. Both arms are
    scored on the SAME test population, so this is paired within replicate.
    """
    return (missed_per_10k(y, scores_lo, tiebreak, k)
            - missed_per_10k(y, scores_hi, tiebreak, k))


def did(delta_contrast_model: float, delta_primary_model: float) -> float:
    """Difference in differences, protocol 5.2.

        DiD = delta(L0) - delta(L3)

    POSITIVE means the auxiliary block reduces misses MORE for the linear
    contrast model than for the primary boosted model -- i.e. capability
    substitutes for collection. This is the H2 estimand.
    """
    return delta_contrast_model - delta_primary_model


def resolution_scan(y, scores_lo, scores_hi, tiebreak, k_star_grid, n=None):
    """Diagnostic: does the endpoint have resolution at these budgets?

    Returns one record per k_star with the paired delta and the precision
    achieved by the better-informed arm. Where precision_hi == 1.0 and
    delta == 0, the endpoint cannot distinguish the arms at that budget and no
    number of replicates will change that.

    Exploratory only -- never used to pick k after seeing confirmatory data.
    """
    y = np.asarray(y)
    n = len(y) if n is None else n
    out = []
    for k_star in k_star_grid:
        k = budget_for(k_star, n)
        if k > len(y):
            continue
        tp_lo = true_positives(y, scores_lo, tiebreak, k)
        tp_hi = true_positives(y, scores_hi, tiebreak, k)
        out.append({
            "k_star": int(k_star),
            "k": k,
            "tp_lo": tp_lo,
            "tp_hi": tp_hi,
            "delta_tp": tp_hi - tp_lo,
            "delta_miss": delta_miss(y, scores_lo, scores_hi, tiebreak, k),
            "precision_hi": tp_hi / k,
            "recall_hi": tp_hi / max(1, int(y.sum())),
            "saturated": tp_hi == k and tp_lo == k,
        })
    return out
