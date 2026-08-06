"""One confirmatory replicate: independent train and test populations.

Protocol v3 section 4.1. This is the piece that replaces the out-of-fold
cross-validation path in `detection_experiment.py`, which section 4.2 forbids
for confirmatory claims: concatenated OOF rankings mix fold structure into a
single list and understate the shift between independently generated
populations, which is the shift a deployed detector actually faces.

Each replicate draws TWO worlds from disjoint RNG streams, fits every
model x tier on the training world only, and scores the test world once.
Nothing is refit, retuned, or reselected using test data.

Failures are logged and counted, never silently redrawn (section 6.3). A seed
whose audit fails is a failed replicate, not a seed to be replaced -- replacing
it would condition the analysis set on the generator behaving, which biases
toward worlds where the gate happens to pass.
"""

from __future__ import annotations

import os
import sys
import traceback

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from degeneracy_audit import DegeneracyError, audit  # noqa: E402
from detection_experiment import _models  # noqa: E402
from dgp import default_config  # noqa: E402
from features import (T1_WALLET_COLS, TIER_COLS, build_entity_features,  # noqa: E402
                      build_wallet_features)
from endpoint import (budget_for, delta_miss, did, missed_per_10k,  # noqa: E402
                      resolution_scan, true_positives)

TIERS = ("T2", "T3", "T4")
PRIMARY_MODEL = "gboost"   # L3 in protocol notation
CONTRAST_MODEL = "logit"   # L0


def _numeric_ids(entities) -> np.ndarray:
    """Tie-break key. Entity ids are 'E<i>'; the int is the reproducible key."""
    return entities.entity_id.str.slice(1).astype(int).to_numpy()


def _world(seed: int, n_entities: int, obfuscation=None, base_rate=None):
    cfg = default_config(seed)
    cfg.n_entities = n_entities
    if obfuscation is not None:
        cfg.obfuscation = obfuscation
    if base_rate is not None:
        cfg.base_rate = base_rate
    from dgp import generate
    data = generate(cfg)
    wf = build_wallet_features(data)
    ef = build_entity_features(data, wf)
    return data, wf, ef, cfg


def run_replicate(replicate_id, train_seed, test_seed, *, n_train, n_test,
                  k_star, obfuscation=None, base_rate=None,
                  k_star_grid=None, audit_train=True):
    """Run one replicate. Returns the machine-readable record of protocol 14.2.

    `status` is OK / FAIL_AUDIT / FAIL_LABEL / FAIL_NUM. On any failure the
    record still returns, carrying the reason -- the caller counts it and moves
    on without substituting a fresh seed.
    """
    rec = {
        "replicate_id": int(replicate_id),
        "train_seed": int(train_seed),
        "test_seed": int(test_seed),
        "status": "OK",
        "n_train": int(n_train),
        "n_test": int(n_test),
        "k_star": int(k_star),
        "audit": {},
        "models": {},
    }
    try:
        tr_data, tr_wf, tr_ef, _ = _world(train_seed, n_train, obfuscation,
                                          base_rate)
        te_data, te_wf, te_ef, _ = _world(test_seed, n_test, obfuscation,
                                          base_rate)

        # Gate runs on the TRAINING world only. Auditing the test world and
        # acting on it would be selection on the outcome population.
        if audit_train:
            try:
                report = audit(tr_ef, tr_wf, TIER_COLS, T1_WALLET_COLS)
                rec["audit"] = {k: report[k] for k in
                                ("gate1_pass", "gate2_pass", "worst_feature",
                                 "worst_auc")}
            except DegeneracyError as e:
                rec["status"] = "FAIL_AUDIT"
                rec["error"] = str(e)[:400]
                return rec

        y_te = te_data["entities"].is_launderer.to_numpy()
        n_pos = int(y_te.sum())
        rec["N_positive_test"] = n_pos
        if n_pos == 0 or n_pos == len(y_te):
            rec["status"] = "FAIL_LABEL"
            rec["error"] = f"degenerate test labels: {n_pos}/{len(y_te)}"
            return rec

        k = budget_for(k_star, len(y_te))
        rec["k"] = k
        tiebreak = _numeric_ids(te_data["entities"])

        y_tr = tr_ef.is_launderer.to_numpy()
        scores = {}
        for model_name in (PRIMARY_MODEL, CONTRAST_MODEL):
            rec["models"][model_name] = {}
            for tier in TIERS:
                cols = TIER_COLS[tier]
                m = _models(train_seed)[model_name]
                m.fit(tr_ef[cols].to_numpy(dtype=float), y_tr)
                s = m.predict_proba(te_ef[cols].to_numpy(dtype=float))[:, 1]
                scores[(model_name, tier)] = s
                rec["models"][model_name][tier] = {
                    "TP": true_positives(y_te, s, tiebreak, k),
                    "MissedPer10k": missed_per_10k(y_te, s, tiebreak, k),
                }

        # paired within-replicate contrasts (protocol 3.4)
        for model_name in (PRIMARY_MODEL, CONTRAST_MODEL):
            rec[f"delta_miss_T2_minus_T4_{model_name}"] = delta_miss(
                y_te, scores[(model_name, "T2")], scores[(model_name, "T4")],
                tiebreak, k)
            rec[f"delta_miss_T2_minus_T3_{model_name}"] = delta_miss(
                y_te, scores[(model_name, "T2")], scores[(model_name, "T3")],
                tiebreak, k)

        rec["DiD_L0_minus_L3"] = did(
            rec[f"delta_miss_T2_minus_T4_{CONTRAST_MODEL}"],
            rec[f"delta_miss_T2_minus_T4_{PRIMARY_MODEL}"])

        # exploratory: does the endpoint resolve anything at other budgets?
        if k_star_grid:
            rec["resolution"] = {
                model_name: resolution_scan(
                    y_te, scores[(model_name, "T2")],
                    scores[(model_name, "T4")], tiebreak, k_star_grid)
                for model_name in (PRIMARY_MODEL, CONTRAST_MODEL)
            }
        return rec

    except Exception as e:  # noqa: BLE001 - any crash is a counted failure
        rec["status"] = "FAIL_NUM"
        rec["error"] = f"{type(e).__name__}: {e}"[:400]
        rec["traceback"] = traceback.format_exc()[-1200:]
        return rec
