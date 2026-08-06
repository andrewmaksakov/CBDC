"""Driver: regenerates every number in the detection pipeline.

    python3 run_all.py [--seed 20260707] [--n-entities 8000] [--delta 0.03]

Order of operations (the audit is a HARD GATE — nothing downstream runs
if it fails):

  1. default world: DGP -> features -> degeneracy audit (gate) ->
     four-tier experiment -> label-permutation negative control ->
     TOST T2 vs T4 (and T2 vs T3).
  2. falsification demo: the surveillance_strong world, where identity
     and watchlist are genuinely informative. The TOST must come out
     NOT-equivalent here (SURVEILLANCE_SUPERIOR expected) — proof the
     harness is not rigged toward the paper's thesis.

Everything lands in results/: results_default.csv, oof_default.csv,
degeneracy_audit_{default,surveillance_strong}.json, tost_*.json,
summary.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from data_loaders import load_synthetic
from degeneracy_audit import DegeneracyError, audit, print_report
from detection_experiment import (label_permutation_control, run_experiment)
from dgp import DGPConfig, default_config, surveillance_strong_config
from equivalence_test import print_tost, tost_equivalence
from features import (T1_WALLET_COLS, TIER_COLS, build_entity_features,
                      build_wallet_features)

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "results")


def run_world(cfg: DGPConfig, delta: float, run_controls: bool) -> dict:
    label = cfg.label
    print(f"\n=== world: {label} (seed={cfg.seed}, "
          f"n_entities={cfg.n_entities}) ===")
    data = load_synthetic(cfg)
    tx = data["transactions"]
    print(f"generated {len(tx)} transactions, "
          f"{len(data['wallets'])} wallets, "
          f"{data['entities'].is_launderer.sum()} launderers")

    wf = build_wallet_features(data)
    ef = build_entity_features(data, wf)

    # gate: degeneracy audit (raises + aborts on failure)
    rep = audit(ef, wf, TIER_COLS, T1_WALLET_COLS)
    print_report(rep)
    with open(f"{RESULTS_DIR}/degeneracy_audit_{label}.json", "w") as f:
        json.dump(rep, f, indent=2)

    results, oof = run_experiment(data, wf, ef, cfg.seed)
    results.to_csv(f"{RESULTS_DIR}/results_{label}.csv", index=False)
    oof.to_csv(f"{RESULTS_DIR}/oof_{label}.csv", index=False)
    print("\nfour-tier results (entity-level, clustered bootstrap 95% CI):")
    for _, r in results.iterrows():
        print(f"  {r.model:6s} {r.tier}: AUC {r.auc:.3f} "
              f"[{r.auc_ci_lo:.3f}, {r.auc_ci_hi:.3f}]   "
              f"AP {r.ap:.3f} [{r.ap_ci_lo:.3f}, {r.ap_ci_hi:.3f}]")

    world = {"config": cfg.to_dict(), "audit": {k: rep[k] for k in
             ("gate1_pass", "gate2_pass", "worst_feature", "worst_auc")},
             "results": results.to_dict("records"), "tost": {}}

    if run_controls:
        perm_auc = label_permutation_control(data, wf, ef, cfg.seed)
        print(f"\nlabel-permutation negative control (T4 gboost): "
              f"AUC = {perm_auc:.3f} (expect ~0.5)")
        world["label_permutation_auc"] = perm_auc

    print()
    # Both metrics, always. AUC saturates at these operating points; AP does
    # not, and the two can return opposite verdicts on identical scores. A
    # verdict without its metric is not interpretable — see equivalence_test.
    for model in ("logit", "gboost"):
        for hi in ("T3", "T4"):
            for metric in ("auc", "ap"):
                res = tost_equivalence(oof, tier_lo="T2", tier_hi=hi,
                                       model=model, delta=delta,
                                       seed=cfg.seed, metric=metric)
                print_tost(res)
                key = f"T2_vs_{hi}_{model}_{metric}"
                world["tost"][key] = res
                with open(f"{RESULTS_DIR}/tost_{label}_{key}.json", "w") as f:
                    json.dump(res, f, indent=2)
    return world


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20260707)
    # n=8000 is canonical (24 Jul): 800 gives ~29 launderers, at which every
    # average-precision comparison is INCONCLUSIVE and the thesis rests on AUC
    # alone at low power. 8000 gives ~388 and separately identifies the tiers.
    ap.add_argument("--n-entities", type=int, default=8000)
    ap.add_argument("--obfuscation", type=float, default=None,
                    help="override default-world obfuscation (0=blatant, "
                         "1=heavy cover); leave unset for the DGP default. "
                         "Does not affect the surveillance_strong world.")
    ap.add_argument("--delta", type=float, default=0.03,
                    help="TOST equivalence margin; applies to AUC directly. "
                         "For AP prefer the reported equiv_bound (the margin "
                         "was set for AUC before any AP result existed).")
    args = ap.parse_args()
    os.makedirs(RESULTS_DIR, exist_ok=True)

    summary = {"seed": args.seed, "delta": args.delta, "worlds": {}}

    cfg = default_config(args.seed)
    cfg.n_entities = args.n_entities
    if args.obfuscation is not None:
        cfg.obfuscation = args.obfuscation
    try:
        summary["worlds"]["default"] = run_world(cfg, args.delta,
                                                 run_controls=True)
    except DegeneracyError as e:
        print(str(e))
        sys.exit(1)

    strong = surveillance_strong_config(args.seed)
    strong.n_entities = args.n_entities
    try:
        summary["worlds"]["surveillance_strong"] = run_world(
            strong, args.delta, run_controls=False)
    except DegeneracyError as e:
        print(str(e))
        sys.exit(1)

    with open(f"{RESULTS_DIR}/summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    strong_verdicts = {k: v["verdict"] for k, v in
                       summary["worlds"]["surveillance_strong"]["tost"].items()}
    print("\n=== harness self-check ===")
    print("surveillance_strong TOST verdicts (must NOT all be EQUIVALENT, "
          "expect SURVEILLANCE_SUPERIOR):")
    for k, v in strong_verdicts.items():
        print(f"  {k}: {v}")
    # Requires a positive SURVEILLANCE_SUPERIOR, not merely the absence of
    # unanimous equivalence: since 24 Jul this loop reports two metrics per
    # comparison, and "not all EQUIVALENT" would be satisfied by a single
    # INCONCLUSIVE, which is an absence of evidence rather than the falsifying
    # result the world was built to produce.
    if not any(v == "SURVEILLANCE_SUPERIOR" for v in strong_verdicts.values()):
        print("WARNING: a world built to falsify the thesis did not return "
              "SURVEILLANCE_SUPERIOR on any comparison — the harness cannot "
              "detect the effect it claims to rule out, do not use.")
        sys.exit(2)
    print("\nall results written to results/")


if __name__ == "__main__":
    main()
