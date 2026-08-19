"""Model-capacity ladder (protocol §3): four rungs, fixed small grids.

Capacity varies along two named axes — nonlinearity (M1→M2) and feature
interactions (M2→M3/M4) — never by brand name. Every rung uses
``class_weight="balanced"`` for continuity with the existing pipeline,
and every rung gets the same inner-CV budget (≤4 configurations,
3-fold entity-grouped, AP-optimized; see ladder_experiment.py).

Grids are FROZEN at the protocol commit. Shrinking (never growing) them
is a §8 feasibility knob.
"""

from __future__ import annotations

from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


def _m1_linear(params, seed, n_features):
    return make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=5000, solver="lbfgs",
                           class_weight="balanced",
                           C=params["C"], random_state=seed))


def _m2_additive(params, seed, n_features):
    return HistGradientBoostingClassifier(
        interaction_cst="no_interactions",
        class_weight="balanced",
        learning_rate=params["learning_rate"],
        max_leaf_nodes=params["max_leaf_nodes"],
        random_state=seed)


def _m3_forest(params, seed, n_features):
    return RandomForestClassifier(
        n_estimators=400, n_jobs=1,
        class_weight="balanced",
        max_features=params["max_features"],
        min_samples_leaf=params["min_samples_leaf"],
        random_state=seed)


def _m4_boosted(params, seed, n_features):
    return HistGradientBoostingClassifier(
        class_weight="balanced",
        learning_rate=params["learning_rate"],
        max_leaf_nodes=params["max_leaf_nodes"],
        random_state=seed)


LADDER = {
    "M1_linear": (_m1_linear, [
        {"C": 0.01}, {"C": 0.1}, {"C": 1.0}, {"C": 10.0},
    ]),
    "M2_additive": (_m2_additive, [
        {"learning_rate": 0.05, "max_leaf_nodes": 15},
        {"learning_rate": 0.05, "max_leaf_nodes": 31},
        {"learning_rate": 0.10, "max_leaf_nodes": 15},
        {"learning_rate": 0.10, "max_leaf_nodes": 31},
    ]),
    "M3_forest": (_m3_forest, [
        {"max_features": "sqrt", "min_samples_leaf": 1},
        {"max_features": "sqrt", "min_samples_leaf": 5},
        {"max_features": 0.5, "min_samples_leaf": 1},
        {"max_features": 0.5, "min_samples_leaf": 5},
    ]),
    "M4_boosted": (_m4_boosted, [
        {"learning_rate": 0.05, "max_leaf_nodes": 15},
        {"learning_rate": 0.05, "max_leaf_nodes": 31},
        {"learning_rate": 0.10, "max_leaf_nodes": 15},
        {"learning_rate": 0.10, "max_leaf_nodes": 31},
    ]),
}

# the reversal pair used on surface/prevalence cells (protocol §5)
SURFACE_MODELS = ("M1_linear", "M4_boosted")


def build(model_name, params, seed, n_features):
    ctor, _ = LADDER[model_name]
    return ctor(params, seed, n_features)
