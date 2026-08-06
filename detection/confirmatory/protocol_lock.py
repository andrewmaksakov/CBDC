"""The freeze: write, validate, and refuse to proceed without signatures.

The decision table's activation rule (section 4) is that confirmatory runs and
`protocol_lock.json` happen only after author sign-off. That rule is worth
nothing if it lives in a markdown file, so it is enforced here: the
confirmatory driver will not start without a lock that validates.

What the lock is for. Every constant that could be tuned toward a preferred
answer -- the alert budget, the tolerance, the precision targets, the seeds,
the model hyperparameters -- is fixed in one file, hashed, and recorded before
any confirmatory data exists. Afterwards the hash either matches what was
registered or it does not. This is what makes "pre-specified" a checkable
claim rather than an assertion about intentions.

    A lock is not a registration. Publishing the hash to a public timestamped
    registry (D23) is a separate step and is what upgrades the manuscript's
    language from "pre-specified" to "preregistered". Do not use the stronger
    word on the strength of this file alone.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import date

LOCK_NAME = "protocol_lock.json"

# Values recommended from the excluded pilot of 6 Aug 2026 (20/20 replicates,
# seeds 900001-900020). PROPOSED, not signed. See README for why D3's original
# k*=50 and D10/D11's tau=0.5 were not carried forward.
PROPOSED = {
    "protocol": "v3 + statistical erratum (2026-08-05)",
    "D1_n_test": 10_000,
    "D2_n_train": 8_000,
    "D3_k_star": 500,
    "D4_delta_star": None,      # deliberately unset -- see note below
    "D5_prevalence": 0.05,
    "D6_regime": "mid/mid (default DGP params)",
    "D7_primary_linkage": "T2-oracle",
    "D8_ci": "two-sided 90% Student-t for the replicate mean; upper endpoint = U",
    "D9_alpha": 0.10,
    "D10_tau_delta": 1.0,
    "D11_tau_did": 2.5,
    "D12_R_min": 20,
    "D13_primary_model": "HistGradientBoostingClassifier(class_weight=balanced)",
    "D14_contrast_model": "LogisticRegression(max_iter=2000, class_weight=balanced) + StandardScaler",
    "D15_h2_confirmatory": True,
    "D17_claim_language": "non-inferiority, never equivalence",
    "D18_ci_method": "student_t_mean",
    "D23_registration": "staged public OSF registration; PENDING",
    "D24_dlt_mechanism": "PENDING -- Andrew Maksakov, deferred to September 2026",
    "seed_offset": 10_000_003,
    "pilot_seeds_burned": list(range(900_001, 900_021)),
    # Must stay under sklearn's random_state ceiling (2**32-1). The original
    # 20260805001 did not, and killed a whole confirmatory attempt.
    "conf_seed_base": 2_026_080_501,
    "R": None,                  # from the sizing rule once tau/delta* are set
    "signatures": [],           # [{"name": ..., "role": ..., "date": "YYYY-MM-DD"}]
}

# D4 is None on purpose. The pilot puts delta_L3 at 7.75 per 10k, and the H1
# verdict is decided almost entirely by delta* rather than by R: the upper
# bound moves only 9.44 -> 8.26 between R=20 and R=200. Writing a default here
# would be choosing the paper's conclusion in a config file. Either set it from
# a workload argument, or run with `primary_report="estimate"` and report the
# quantity with its interval instead of a binary verdict.

REQUIRED_SIGNERS = ("lead author",)


class LockError(RuntimeError):
    """Raised when the freeze is absent, unsigned, or internally inconsistent."""


def _canonical(lock: dict) -> bytes:
    """Hash input: everything except the hash itself, key order normalised."""
    body = {k: v for k, v in lock.items() if k != "lock_sha256"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def compute_hash(lock: dict) -> str:
    return hashlib.sha256(_canonical(lock)).hexdigest()


def write_template(path: str, **overrides) -> dict:
    """Write an UNSIGNED lock template for the authors to complete."""
    lock = dict(PROPOSED)
    lock.update(overrides)
    lock["written"] = date.today().isoformat()
    lock["lock_sha256"] = compute_hash(lock)
    with open(path, "w") as f:
        json.dump(lock, f, indent=2)
    return lock


def load(path: str) -> dict:
    if not os.path.exists(path):
        raise LockError(
            f"no protocol lock at {path}. Confirmatory runs require a signed "
            f"freeze (decision table section 4). Write a template with:\n"
            f"    python3 -c \"import protocol_lock as p; "
            f"p.write_template('{path}')\"\n"
            f"then complete D4/R, add signatures, and re-run.")
    with open(path) as f:
        return json.load(f)


def validate(lock: dict, *, allow_unsigned=False) -> None:
    """Raise unless this lock authorises a confirmatory run."""
    recorded = lock.get("lock_sha256")
    actual = compute_hash(lock)
    if recorded != actual:
        raise LockError(
            "lock hash mismatch: the file was edited after it was written. "
            f"recorded {recorded}, actual {actual}. If the edit was "
            "intentional, rewrite the lock deliberately and note the change; "
            "a silently mutated freeze is not a freeze.")

    if not allow_unsigned:
        sigs = lock.get("signatures") or []
        names = {s.get("role", "").lower() for s in sigs}
        missing = [r for r in REQUIRED_SIGNERS if r not in names]
        if missing:
            raise LockError(
                f"lock is unsigned (missing: {', '.join(missing)}). The "
                f"decision table's activation rule requires sign-off before "
                f"any confirmatory run. Add to 'signatures': "
                f'[{{"name": "...", "role": "lead author", "date": "..."}}] '
                f"and rewrite the hash.")

    if lock.get("R") in (None, 0):
        raise LockError("lock has no R. Derive it from the excluded pilot "
                        "(inference.size_from_pilot) before freezing.")

    burned = set(lock.get("pilot_seeds_burned") or [])
    base, R = lock.get("conf_seed_base"), lock.get("R")
    if base is None:
        raise LockError("lock has no conf_seed_base; confirmatory seeds must "
                        "be written into the freeze, not chosen at run time.")
    overlap = burned & set(range(base, base + R))
    if overlap:
        raise LockError(
            f"CONF_SEEDS overlap burned PILOT_SEEDS at {sorted(overlap)[:5]}. "
            "Pilot seeds are excluded from confirmatory analysis permanently "
            "(protocol 6.1 step 3).")

    # Caught the hard way on 6 Aug: conf_seed_base 20260805001 exceeds
    # sklearn's random_state ceiling, so every confirmatory replicate died with
    # FAIL_NUM 20 replicates in. replicate.model_seed() now narrows the seed,
    # but the gate should refuse a lock that cannot execute, not discover it
    # mid-run.
    from replicate import SKLEARN_SEED_MAX
    if base + R > SKLEARN_SEED_MAX:
        raise LockError(
            f"conf_seed_base {base} + R {R} exceeds sklearn's random_state "
            f"ceiling ({SKLEARN_SEED_MAX}). Model seeds are narrowed by "
            f"replicate.model_seed(), which is deterministic but means the "
            f"model seed is not the protocol seed. Confirm that is intended, "
            f"or choose a base below the ceiling.")

    if lock.get("D3_k_star", 0) < 300:
        raise LockError(
            f"k*={lock.get('D3_k_star')} is at or below the saturated regime "
            "measured in the 6 Aug pilot (k*<=300 saturated in >=90% of "
            "replicates). A non-inferiority test at that budget cannot fail. "
            "Override only with a written amendment explaining why.")


def conf_seeds(lock: dict) -> list[int]:
    base, R = lock["conf_seed_base"], lock["R"]
    return [base + i for i in range(R)]
