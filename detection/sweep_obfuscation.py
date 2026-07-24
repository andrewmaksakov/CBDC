"""Robustness surface: does the capability-dependence finding survive moving
the one free parameter of the data-generating process?

The paper's central claim is that the marginal value of identity access is a
function of detector capability, not of the data. The obvious objection to any
synthetic ablation is that the analyst chose the generating process that gave
them their answer. The direct rebuttal is not to defend a single choice but to
vary the parameter that most plausibly drives the result --- here, laundering
`obfuscation` (0 = blatant layering, 1 = heavy behavioral cover) --- and show
the qualitative verdict is stable across the range.

This driver reuses the SAME audit, experiment, and equivalence functions as
run_all.py, so there is no methodological drift between the point estimate of
record (results/, obf=0.6) and this surface: only the obfuscation value and the
seed change. For each (obfuscation, seed) it runs the full default-world
pipeline at n=8000 and records the T2-vs-T3 and T2-vs-T4 equivalence verdict on
BOTH metrics. Multiple seeds per level distinguish a real obfuscation effect
from single-seed bootstrap noise (the reason the verdict at any one point can
wobble across the equivalence margin).

Output: results/robustness_obfuscation.csv (one row per obf x seed x model x
comparison x metric) plus a printed cross-seed summary. Does NOT touch the
canonical results/ point-estimate files.

    python3 sweep_obfuscation.py
    python3 sweep_obfuscation.py --n-entities 8000 \
        --obfuscations 0.5,0.6,0.7,0.8,0.9 --seeds 20260707,20260708,20260709
"""

from __future__ import annotations

import argparse
import dataclasses
import os

import pandas as pd

from data_loaders import load_synthetic
from degeneracy_audit import DegeneracyError, audit
from detection_experiment import run_experiment
from dgp import default_config
from equivalence_test import tost_equivalence
from features import (T1_WALLET_COLS, TIER_COLS, build_entity_features,
                      build_wallet_features)

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "results")

MODELS = ("logit", "gboost")
HI_TIERS = ("T3", "T4")
METRICS = ("auc", "ap")


def run_point(n_entities: int, obfuscation: float, seed: int,
              delta: float) -> list[dict]:
    """One (obfuscation, seed) cell: full default-world pipeline, all
    equivalence verdicts. Returns a list of flat records."""
    cfg = dataclasses.replace(default_config(seed),
                              n_entities=n_entities, obfuscation=obfuscation)
    data = load_synthetic(cfg)
    wf = build_wallet_features(data)
    ef = build_entity_features(data, wf)

    # The gate still runs: a robustness point that only holds because the DGP
    # degenerated is not evidence. Record the audit rather than abort the sweep,
    # so a failing cell is visible instead of silently dropped.
    rep = audit(ef, wf, TIER_COLS, T1_WALLET_COLS)

    results, oof = run_experiment(data, wf, ef, cfg.seed)
    ap = results.pivot(index="model", columns="tier", values="ap")
    auc = results.pivot(index="model", columns="tier", values="auc")

    rows = []
    for model in MODELS:
        for hi in HI_TIERS:
            for metric in METRICS:
                r = tost_equivalence(oof, tier_lo="T2", tier_hi=hi,
                                     model=model, delta=delta,
                                     seed=cfg.seed, metric=metric)
                rows.append({
                    "obfuscation": obfuscation,
                    "seed": seed,
                    "n_entities": n_entities,
                    "n_launderers": r["n_launderers"],
                    "model": model,
                    "comparison": f"T2_vs_{hi}",
                    "metric": metric,
                    "d_point": r["d_point"],
                    "ci_lo": r["d_ci90"][0],
                    "ci_hi": r["d_ci90"][1],
                    "equiv_bound": r["equiv_bound"],
                    "verdict": r["verdict"],
                    "T2_auc": auc.loc[model, "T2"],
                    "hi_auc": auc.loc[model, hi],
                    "T2_ap": ap.loc[model, "T2"],
                    "hi_ap": ap.loc[model, hi],
                    "audit_pass": bool(rep["gate1_pass"] and rep["gate2_pass"]),
                    "audit_worst_feature": rep["worst_feature"],
                    "audit_worst_auc": rep["worst_auc"],
                })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-entities", type=int, default=8000)
    ap.add_argument("--obfuscations", type=str, default="0.5,0.6,0.7,0.8,0.9")
    ap.add_argument("--seeds", type=str,
                    default="20260707,20260708,20260709")
    ap.add_argument("--delta", type=float, default=0.03)
    args = ap.parse_args()

    obfs = [float(x) for x in args.obfuscations.split(",")]
    seeds = [int(x) for x in args.seeds.split(",")]
    os.makedirs(RESULTS_DIR, exist_ok=True)

    all_rows = []
    for obf in obfs:
        for seed in seeds:
            try:
                rows = run_point(args.n_entities, obf, seed, args.delta)
            except DegeneracyError as e:
                print(f"[obf={obf} seed={seed}] DEGENERACY GATE FAILED: {e}")
                continue
            all_rows.extend(rows)
            g = next(r for r in rows if r["model"] == "gboost"
                     and r["comparison"] == "T2_vs_T4" and r["metric"] == "ap")
            print(f"obf={obf:.2f} seed={seed}: {g['n_launderers']:>3} laund, "
                  f"gboost T2vT4 AP {g['d_point']:+.4f} [{g['verdict']}]  "
                  f"audit {'PASS' if g['audit_pass'] else 'FAIL'}")

    df = pd.DataFrame(all_rows)
    out = f"{RESULTS_DIR}/robustness_obfuscation.csv"
    df.to_csv(out, index=False)
    print(f"\nwrote {out}  ({len(df)} rows, "
          f"{len(obfs)} obfuscations x {len(seeds)} seeds)")

    # Cross-seed summary: is the verdict stable per (obf, model, comparison,
    # metric)? A surface reviewers can trust needs the verdict, not just the
    # point estimate, to be seed-stable.
    print("\n=== cross-seed verdict stability (T2 vs T4) ===")
    print(f"{'obf':>4} {'model':7s} {'metric':6s} "
          f"{'median d':>9} {'verdicts across seeds':30s} stable?")
    sub = df[df.comparison == "T2_vs_T4"]
    for (obf, model, metric), g in sub.groupby(
            ["obfuscation", "model", "metric"]):
        verds = list(g.verdict)
        stable = len(set(verds)) == 1
        med = g.d_point.median()
        print(f"{obf:>4.2f} {model:7s} {metric:6s} {med:+9.4f} "
              f"{','.join(v[:4] for v in verds):30s} "
              f"{'yes' if stable else 'NO'}")


if __name__ == "__main__":
    main()
