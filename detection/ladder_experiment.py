"""E1–E6 replicate engine (protocol §§3–6).

One call to ``run_replicate`` = one (world, replicate) unit:

    generate world -> features -> degeneracy audit (gate) -> entity folds
    -> per model: nested per-outer-fold tuning on T4 -> per-tier OOF
    scores (selected config reused across tiers within the fold)
    -> metrics (AP primary; recall/precision at the 5% alert budget
    co-primary; AUC secondary) -> tier increments.

Leakage discipline: configuration selection happens inside each outer
training set (3-fold entity-grouped inner CV, AP-optimized, on T4
features); the per-fold winner is reused for every tier in that fold.
Folds split on entities (inherited from detection_experiment).
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold

from degeneracy_audit import DegeneracyError, audit
from detection_experiment import N_FOLDS, _entity_folds
from features import (T1_WALLET_COLS, TIER_COLS, build_entity_features,
                      build_wallet_features)
from dgp import generate
from ladder_config import LADDER, build

ALERT_BUDGET = 0.05          # co-primary operating point: top 5% of entities
INNER_FOLDS = 3

TIERS = ("T1", "T2", "T3", "T4")


def budget_metrics(y, score, budget=ALERT_BUDGET):
    """Recall and precision when exactly ceil(budget*n) entities are alerted."""
    n = len(y)
    k = int(np.ceil(budget * n))
    order = np.argsort(-score, kind="stable")
    alerted = order[:k]
    tp = int(y[alerted].sum())
    pos = int(y.sum())
    return {
        "recall_at_budget": tp / pos if pos else float("nan"),
        "precision_at_budget": tp / k,
        "missed_per_10k": (pos - tp) / n * 10_000,
        "alerts_per_10k": k / n * 10_000,
    }


def _inner_select(X, y, model_name, seed):
    """3-fold entity-grouped (one row per entity => plain stratified) inner
    CV over the rung's frozen grid; returns the AP-winning param dict."""
    _, grid = LADDER[model_name]
    if len(grid) == 1:
        return grid[0]
    skf = StratifiedKFold(n_splits=INNER_FOLDS, shuffle=True,
                          random_state=seed + 1)
    best, best_ap = None, -np.inf
    for params in grid:
        aps = []
        for tr, te in skf.split(X, y):
            m = build(model_name, params, seed, X.shape[1])
            m.fit(X[tr], y[tr])
            aps.append(average_precision_score(y[te],
                                               m.predict_proba(X[te])[:, 1]))
        ap = float(np.mean(aps))
        if ap > best_ap:
            best, best_ap = params, ap
    return best


def _oof_ladder(entities, wallet_feats, entity_feats, folds, model_name,
                seed):
    """Per-tier OOF entity scores with per-outer-fold config selection on T4."""
    ef = entity_feats.set_index("entity_id").loc[folds.index]
    y = ef.is_launderer.to_numpy()
    X_by_tier = {t: ef[cols].to_numpy(dtype=float)
                 for t, cols in TIER_COLS.items()}

    # T1 operates on wallets; reuse the same per-fold selected config
    wf = wallet_feats.merge(
        entities[["entity_id", "is_launderer"]], on="entity_id")
    wf = wf.assign(fold=wf.entity_id.map(folds))
    Xw = wf[T1_WALLET_COLS].to_numpy(dtype=float)
    yw = wf.is_launderer.to_numpy()

    scores = {t: np.full(len(ef), np.nan) for t in TIERS}
    chosen = []
    for k in range(N_FOLDS):
        tr = (folds != k).values
        te = (folds == k).values
        params = _inner_select(X_by_tier["T4"][tr], y[tr], model_name, seed)
        chosen.append(params)
        for t in ("T2", "T3", "T4"):
            m = build(model_name, params, seed, X_by_tier[t].shape[1])
            m.fit(X_by_tier[t][tr], y[tr])
            scores[t][te] = m.predict_proba(X_by_tier[t][te])[:, 1]
        trw = (wf.fold != k).to_numpy()
        tew = (wf.fold == k).to_numpy()
        mw = build(model_name, params, seed, Xw.shape[1])
        mw.fit(Xw[trw], yw[trw])
        wf.loc[tew, "score"] = mw.predict_proba(Xw[tew])[:, 1]
    ent_t1 = (wf.groupby("entity_id").score.max()
              .reindex(folds.index).to_numpy())
    scores["T1"] = ent_t1
    return y, scores, chosen


def run_replicate(cfg, models, seed):
    """One world × one replicate. Returns dict (JSON-serializable)."""
    data = generate(cfg)
    wf = build_wallet_features(data)
    ef = build_entity_features(data, wf)
    out = {"label": cfg.label, "seed": seed, "config": cfg.to_dict(),
           "gate": "pass", "models": {}}
    try:
        audit(ef, wf, TIER_COLS, T1_WALLET_COLS)
    except DegeneracyError as e:
        out["gate"] = f"excluded_by_gate: {e}"
        return out

    folds = _entity_folds(data["entities"], seed)
    for model_name in models:
        y, scores, chosen = _oof_ladder(
            data["entities"], wf, ef, folds, model_name, seed)
        tiers = {}
        for t in TIERS:
            s = scores[t]
            m = {"ap": float(average_precision_score(y, s)),
                 "auc": float(roc_auc_score(y, s))}
            m.update(budget_metrics(y, s))
            tiers[t] = m
        incr = {}
        for metric in ("ap", "recall_at_budget"):
            incr[metric] = {
                "dL": tiers["T2"][metric] - tiers["T1"][metric],
                "dI": tiers["T3"][metric] - tiers["T2"][metric],
                "dW": tiers["T4"][metric] - tiers["T3"][metric],
                "dF": tiers["T4"][metric] - tiers["T2"][metric],
            }
        out["models"][model_name] = {
            "tiers": tiers, "increments": incr, "chosen_params": chosen,
            "n_entities": int(len(y)), "n_launderers": int(y.sum()),
        }
    return out
