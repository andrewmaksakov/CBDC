"""Endpoint semantics tests.

The sign conventions here are the whole ballgame: a flipped sign turns
"withholding identity costs detection" into its opposite and the error is
invisible in aggregate output. Every convention below is asserted against a
hand-built case where the right answer is obvious by inspection.
"""

import numpy as np

from endpoint import (budget_for, delta_miss, did, missed_per_10k,
                      resolution_scan, select_alerts, true_positives)


def test_budget_scales_per_10k():
    assert budget_for(50, 10_000) == 50
    assert budget_for(50, 8_000) == 40
    assert budget_for(500, 8_000) == 400
    assert budget_for(1, 100) == 1          # floors at 1, never 0
    assert budget_for(10_000, 500) == 500   # whole population


def test_tiebreak_lower_id_wins():
    scores = np.array([0.9, 0.9, 0.9, 0.1])
    ids = np.array([7, 2, 5, 1])
    # all three top scores tie -> the two lowest ids among them win
    picked = sorted(ids[select_alerts(scores, ids, 2)])
    assert picked == [2, 5]


def test_tiebreak_rejects_string_ids():
    # "E10" < "E2" lexicographically -- silently wrong, so refuse it
    try:
        select_alerts(np.array([1.0, 2.0]), np.array(["E10", "E2"]), 1)
    except TypeError:
        return
    raise AssertionError("string tiebreak should raise")


def test_budget_cannot_exceed_population():
    try:
        select_alerts(np.array([1.0, 2.0]), np.array([0, 1]), 5)
    except ValueError:
        return
    raise AssertionError("k > n should raise")


def test_missed_per_10k_formula():
    # n=100, 10 illicit, budget 5, all 5 alerts correct -> 5 missed of 10
    y = np.array([1] * 10 + [0] * 90)
    ids = np.arange(100)
    scores = np.concatenate([np.linspace(1.0, 0.9, 10), np.zeros(90)])
    assert true_positives(y, scores, ids, 5) == 5
    # 10000 * (10 - 5) / 100 = 500
    assert missed_per_10k(y, scores, ids, 5) == 500.0


def test_perfect_detector_misses_only_what_budget_forbids():
    y = np.array([1] * 10 + [0] * 90)
    ids = np.arange(100)
    scores = np.concatenate([np.ones(10), np.zeros(90)])
    # budget 10 = exactly the positives -> nothing missed
    assert missed_per_10k(y, scores, ids, 10) == 0.0


def test_delta_sign_positive_when_lo_arm_is_worse():
    """POSITIVE delta must mean the lo (T2) arm misses MORE."""
    y = np.array([1, 1, 0, 0, 0, 0, 0, 0, 0, 0])
    ids = np.arange(10)
    # hi arm ranks both illicit first; lo arm ranks only one
    scores_hi = np.array([0.9, 0.8, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    scores_lo = np.array([0.9, 0.05, 0.8, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    d = delta_miss(y, scores_lo, scores_hi, ids, k=2)
    assert d > 0, "lo arm catches fewer -> delta must be positive"
    # lo catches 1 of 2, hi catches 2 of 2 -> 10000*(1)/10 = 1000
    assert d == 1000.0


def test_delta_zero_when_arms_agree():
    y = np.array([1, 1, 0, 0, 0, 0, 0, 0, 0, 0])
    ids = np.arange(10)
    s = np.array([0.9, 0.8, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    assert delta_miss(y, s, s, ids, k=2) == 0.0


def test_did_sign_positive_when_linear_model_gains_more():
    """DiD > 0 = the auxiliary block helps the linear model more."""
    assert did(delta_contrast_model=10.0, delta_primary_model=2.0) == 8.0
    assert did(delta_contrast_model=2.0, delta_primary_model=10.0) == -8.0


def test_resolution_scan_flags_the_saturated_regime():
    """The ceiling this endpoint has to be protected against."""
    # 100 entities, 50 illicit, both arms rank all illicit above all legit.
    # At any budget below 50 BOTH arms score perfect precision -> no signal.
    y = np.array([1] * 50 + [0] * 50)
    ids = np.arange(100)
    strong = np.concatenate([np.linspace(1.0, 0.6, 50), np.zeros(50)])
    weaker = np.concatenate([np.linspace(1.0, 0.6, 50), np.zeros(50)])
    scan = {r["k_star"]: r for r in
            resolution_scan(y, weaker, strong, ids, [100, 500, 4000, 8000])}
    assert scan[100]["saturated"] is True
    assert scan[100]["delta_miss"] == 0.0
    assert scan[100]["precision_hi"] == 1.0
    # k_star=4000 -> k=40, still under the 50 positives: STILL saturated
    assert scan[4000]["k"] == 40
    assert scan[4000]["saturated"] is True
    # only once the budget exceeds the positive count does precision fall
    assert scan[8000]["k"] == 80
    assert scan[8000]["saturated"] is False
    assert scan[8000]["precision_hi"] < 1.0


def test_resolution_scan_sees_signal_when_arms_differ():
    y = np.array([1] * 20 + [0] * 80)
    ids = np.arange(100)
    strong = np.concatenate([np.linspace(1.0, 0.8, 20), np.zeros(80)])
    # weak arm buries 10 illicit at the bottom
    weaker = np.concatenate([np.linspace(1.0, 0.9, 10), np.full(10, 0.01),
                             np.full(80, 0.5)])
    scan = {r["k_star"]: r for r in resolution_scan(y, weaker, strong, ids,
                                                    [2000])}
    assert scan[2000]["delta_miss"] > 0
    assert scan[2000]["saturated"] is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS: {fn.__name__}")
    print(f"\nall {len(fns)} endpoint tests passed")
