"""Replicate-level inference: non-inferiority, gatekeeping, pilot sizing.

Implements the statistical erratum to protocol v3 (E1-E4).

Three things here differ from the pilot pipeline and each was a correction:

E1  The decision is ONE-SIDED non-inferiority, not two-sided equivalence.
    "U <= delta" establishes only that T2 is not unacceptably worse than T4.
    Calling that "equivalent" claims the two-sided result, which was never
    tested. The word matters in the manuscript and so it matters here.

E2  H2 is GATED on H1. Testing H2 after H1 returns any verdict -- including
    inconclusive -- is sequential reporting with no multiplicity protection.

E3  The interval is a Student-t CI for the MEAN of the replicate estimates.
    Raw percentiles of {delta_r} describe between-world dispersion and are not
    a confidence interval for the mean; reporting them as one understates
    uncertainty about the quantity actually being claimed.
"""

from __future__ import annotations

import math

import numpy as np
from scipy import stats

__all__ = [
    "mean_ci",
    "non_inferiority",
    "gated_did",
    "replicates_needed",
    "size_from_pilot",
]

NON_INFERIOR = "NON_INFERIOR"
SURVEILLANCE_SUPERIOR = "SURVEILLANCE_SUPERIOR"
INCONCLUSIVE = "INCONCLUSIVE"
UNDETERMINED = "UNDETERMINED"


def mean_ci(values, alpha=0.10):
    """Two-sided Student-t CI for the mean of the replicate estimates (E3).

    alpha=0.10 gives a 90% two-sided interval whose upper endpoint implements a
    one-sided 5% non-inferiority decision (decision table D8/D9).
    """
    x = np.asarray([v for v in values if v is not None], dtype=float)
    r = len(x)
    if r < 2:
        return {"mean": float(x[0]) if r else None, "sd": None, "R_ok": r,
                "ci_lo": None, "ci_hi": None, "alpha": alpha,
                "note": "fewer than 2 successful replicates"}
    mean = float(x.mean())
    sd = float(x.std(ddof=1))
    half = float(stats.t.ppf(1 - alpha / 2, df=r - 1) * sd / math.sqrt(r))
    return {"mean": mean, "sd": sd, "R_ok": r, "ci_lo": mean - half,
            "ci_hi": mean + half, "half_width": half, "alpha": alpha}


def non_inferiority(values, delta_star, alpha=0.10):
    """H1 (E1). Positive delta = T2 misses MORE than T4.

    NON_INFERIOR            U <= delta*   withholding auxiliary info costs
                                          at most the tolerated amount
    SURVEILLANCE_SUPERIOR   L >  delta*   auxiliary info helps beyond tolerance
    INCONCLUSIVE            L <= delta* < U
    """
    ci = mean_ci(values, alpha=alpha)
    out = dict(ci)
    out["delta_star"] = delta_star
    if ci.get("ci_hi") is None:
        out["verdict"] = UNDETERMINED
        return out
    if ci["ci_hi"] <= delta_star:
        out["verdict"] = NON_INFERIOR
    elif ci["ci_lo"] > delta_star:
        out["verdict"] = SURVEILLANCE_SUPERIOR
    else:
        out["verdict"] = INCONCLUSIVE
    # A verdict from an endpoint with no observed variation was not at risk of
    # coming out otherwise. Surface it rather than let it read as a finding.
    if ci.get("sd") == 0.0 and ci["mean"] == 0.0:
        out["degenerate"] = True
        out["degenerate_note"] = (
            "every replicate returned delta=0 exactly: the budget is in the "
            "saturated regime where both arms review identical entities. This "
            "verdict is forced by the operating point, not measured.")
    return out


def gated_did(did_values, h1_verdict, alpha=0.10):
    """H2 (E2): confirmatory ONLY if H1 established non-inferiority.

    DiD > 0 means the auxiliary block helps the linear model more than the
    boosted one -- the "capacity conditions the value of identity" claim.
    Confirmatory support requires the whole interval above zero.
    """
    ci = mean_ci(did_values, alpha=alpha)
    out = dict(ci)
    out["h1_verdict"] = h1_verdict
    if h1_verdict != NON_INFERIOR:
        out["status"] = "DESCRIPTIVE_ONLY"
        out["confirmatory"] = False
        out["note"] = (
            "H1 did not establish non-inferiority, so H2 is descriptive. The "
            "manuscript may NOT claim confirmatory evidence that model "
            "capacity conditions the value of identity-linked auxiliary "
            "information.")
        return out
    out["confirmatory"] = True
    if ci.get("ci_lo") is None:
        out["status"] = UNDETERMINED
    elif ci["ci_lo"] > 0:
        out["status"] = "MODERATION_SUPPORTED"
    else:
        out["status"] = "MODERATION_NOT_SUPPORTED"
        out["note"] = ("drop the 'capacity conditions the value of identity "
                       "access' headline; report DiD as inconclusive")
    return out


def replicates_needed(sd, tau, alpha=0.10, r_min=20):
    """R for a target CI half-width tau (E4).

        R >= ceil((z_{1-alpha/2} * sd / tau)^2)

    z is used as the pilot-stage approximation to t, per the protocol.
    """
    if sd is None or tau is None or tau <= 0:
        return r_min
    z = float(stats.norm.ppf(1 - alpha / 2))
    return max(r_min, int(math.ceil((z * sd / tau) ** 2)))


def size_from_pilot(delta_values, did_values, tau_delta, tau_did,
                    alpha=0.10, r_min=20, h2_confirmatory=True):
    """Confirmatory R from the excluded pilot (E4).

    Sized for BOTH H1 and H2 when H2 is confirmatory -- sizing on delta alone
    under-powers the moderation test that the headline depends on.
    """
    sd_d = mean_ci(delta_values, alpha).get("sd")
    sd_did = mean_ci(did_values, alpha).get("sd")
    r_delta = replicates_needed(sd_d, tau_delta, alpha, r_min)
    r_did = (replicates_needed(sd_did, tau_did, alpha, r_min)
             if h2_confirmatory else r_min)
    return {
        "sd_delta": sd_d,
        "sd_did": sd_did,
        "tau_delta": tau_delta,
        "tau_did": tau_did,
        "R_delta": r_delta,
        "R_did": r_did,
        "R_min": r_min,
        "h2_confirmatory": h2_confirmatory,
        "R": max(r_delta, r_did, r_min),
    }
