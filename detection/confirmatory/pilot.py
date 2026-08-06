"""Excluded Monte Carlo pilot: sizes R, and maps where the endpoint resolves.

Protocol v3 section 6.1 plus erratum E4.

The pilot does two jobs. Its protocol job is to estimate SD(delta) and SD(DiD)
so the confirmatory replicate count R can be derived from a precision target
rather than guessed. Its second job is diagnostic: it sweeps a grid of alert
budgets and reports where the endpoint has any resolution at all, because
k* = 50 per 10,000 sits in a regime where every arm reviews the same entities
and delta is identically zero. Freezing a budget there would produce a
non-inferiority PASS that no data could have contradicted.

    THESE SEEDS ARE BURNED. PILOT_SEEDS are excluded from confirmatory
    analysis permanently (protocol 6.1 step 3). Do not reuse them, and do not
    pick k* by looking at confirmatory data later -- that is the peeking this
    design exists to prevent.

Usage:
    python3 pilot.py                       # 20 replicates, default grid
    python3 pilot.py --replicates 8        # quick smoke run
    python3 pilot.py --k-star 500          # size R at a chosen budget
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

# Replicates are the unit of parallelism, so each worker gets ONE thread.
# Left at defaults, HistGradientBoosting's OpenMP pool and the BLAS backend
# each spawn a thread per core inside every worker; with W workers that is
# W x cores threads contending for cores, and the run gets slower as workers
# are added. Must precede the numpy/sklearn import.
for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
           "NUMEXPR_NUM_THREADS"):
    os.environ.setdefault(_v, "1")

from concurrent.futures import ProcessPoolExecutor, as_completed  # noqa: E402

import numpy as np  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inference import mean_ci, size_from_pilot  # noqa: E402
from replicate import CONTRAST_MODEL, PRIMARY_MODEL, run_replicate  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "results")

# Protocol 6.1 / decision table section 3. Burned on use.
PILOT_SEED_BASE = 900_001
SEED_OFFSET = 10_000_003          # test-stream offset (decision table)

DEFAULT_K_STAR_GRID = [50, 100, 200, 300, 400, 500, 625, 750, 1000, 1250,
                       1500, 2000]


def _job(args):
    i, seed, kw = args
    return run_replicate(i, seed, seed + SEED_OFFSET, **kw)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--replicates", type=int, default=20,
                    help="R_pilot (protocol default 20)")
    ap.add_argument("--n-train", type=int, default=8000)
    ap.add_argument("--n-test", type=int, default=10000)
    ap.add_argument("--k-star", type=int, default=500,
                    help="alerts per 10,000 used for the SIZING estimate. "
                         "NOTE: decision-table D3 proposes 50, which the "
                         "resolution scan shows is saturated; 500 is a "
                         "provisional evidence-led default and is NOT signed.")
    ap.add_argument("--tau-delta", type=float, default=0.5,
                    help="target CI half-width for mean delta (D10)")
    ap.add_argument("--tau-did", type=float, default=0.5, help="(D11)")
    ap.add_argument("--alpha", type=float, default=0.10, help="(D9)")
    ap.add_argument("--r-min", type=int, default=20, help="(D12)")
    ap.add_argument("--no-h2", action="store_true",
                    help="H2 demoted to descriptive; size on delta only")
    ap.add_argument("--workers", type=int,
                    default=max(1, (os.cpu_count() or 4) - 2))
    args = ap.parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)

    seeds = [PILOT_SEED_BASE + i for i in range(args.replicates)]
    kw = dict(n_train=args.n_train, n_test=args.n_test, k_star=args.k_star,
              k_star_grid=DEFAULT_K_STAR_GRID)

    print(f"excluded pilot: {args.replicates} replicates, "
          f"n_train={args.n_train}, n_test={args.n_test}, "
          f"k*={args.k_star}/10k, {args.workers} workers")
    print(f"PILOT_SEEDS {seeds[0]}..{seeds[-1]} — burned, never confirmatory\n",
          flush=True)

    records = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_job, (i, s, kw)): i
                for i, s in enumerate(seeds)}
        for done, fut in enumerate(as_completed(futs), 1):
            rec = fut.result()
            records.append(rec)
            flag = "" if rec["status"] == "OK" else f"  <-- {rec['status']}"
            d = rec.get(f"delta_miss_T2_minus_T4_{PRIMARY_MODEL}")
            print(f"  [{done}/{len(seeds)}] rep {rec['replicate_id']:>3} "
                  f"{rec['status']:<11} "
                  f"delta_L3={'n/a' if d is None else f'{d:+.1f}'}{flag}",
                  flush=True)

    records.sort(key=lambda r: r["replicate_id"])
    with open(os.path.join(OUT_DIR, "pilot_replicates.json"), "w") as f:
        json.dump(records, f, indent=2)

    ok = [r for r in records if r["status"] == "OK"]
    failed = [r for r in records if r["status"] != "OK"]
    with open(os.path.join(OUT_DIR, "failures.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["replicate_id", "train_seed", "test_seed", "status",
                    "error"])
        for r in failed:
            w.writerow([r["replicate_id"], r["train_seed"], r["test_seed"],
                        r["status"], r.get("error", "")])

    print(f"\n{len(ok)}/{len(records)} replicates OK, "
          f"{len(failed)} failed (logged, NOT redrawn)")
    if not ok:
        sys.exit("no successful replicates; diagnose the generator")

    deltas = [r[f"delta_miss_T2_minus_T4_{PRIMARY_MODEL}"] for r in ok]
    deltas_l0 = [r[f"delta_miss_T2_minus_T4_{CONTRAST_MODEL}"] for r in ok]
    dids = [r["DiD_L0_minus_L3"] for r in ok]

    sizing = size_from_pilot(deltas, dids, args.tau_delta, args.tau_did,
                             alpha=args.alpha, r_min=args.r_min,
                             h2_confirmatory=not args.no_h2)

    print(f"\n=== pilot estimates at k*={args.k_star}/10k ===")
    for name, vals in (("delta_L3", deltas), ("delta_L0", deltas_l0),
                       ("DiD", dids)):
        ci = mean_ci(vals, args.alpha)
        sd = "n/a" if ci["sd"] is None else f"{ci['sd']:.3f}"
        print(f"  {name:<9} mean={ci['mean']:+.3f}  sd={sd}  "
              f"R_ok={ci['R_ok']}")

    print(f"\n=== confirmatory sizing (E4) ===")
    print(f"  R_delta = {sizing['R_delta']}   (tau={args.tau_delta})")
    print(f"  R_DiD   = {sizing['R_did']}   (tau={args.tau_did}, "
          f"{'confirmatory' if sizing['h2_confirmatory'] else 'descriptive'})")
    print(f"  R_min   = {sizing['R_min']}")
    print(f"  --> R   = {sizing['R']}")

    # resolution scan, averaged over replicates
    print(f"\n=== resolution scan (exploratory; pick k* HERE, not later) ===")
    print(f"  {'k*/10k':>7} {'k':>5} | {'dTP L3':>7} {'dTP L0':>7} "
          f"{'DiD':>6} | {'prec L3':>8} | saturated")
    print("  " + "-" * 62)
    scan_rows = []
    for j, k_star in enumerate(DEFAULT_K_STAR_GRID):
        agg = {}
        for model in (PRIMARY_MODEL, CONTRAST_MODEL):
            pts = [r["resolution"][model][j] for r in ok if "resolution" in r]
            if not pts:
                continue
            agg[model] = {
                "delta_tp": float(np.mean([p["delta_tp"] for p in pts])),
                "delta_miss": float(np.mean([p["delta_miss"] for p in pts])),
                "precision_hi": float(np.mean([p["precision_hi"] for p in pts])),
                "sat_frac": float(np.mean([p["saturated"] for p in pts])),
                "k": pts[0]["k"],
            }
        if not agg:
            continue
        a, b = agg[PRIMARY_MODEL], agg[CONTRAST_MODEL]
        did_k = b["delta_miss"] - a["delta_miss"]
        sat = "ALL" if a["sat_frac"] == 1.0 else (
            "-" if a["sat_frac"] == 0 else f"{a['sat_frac']:.0%}")
        print(f"  {k_star:>7} {a['k']:>5} | {a['delta_tp']:>7.1f} "
              f"{b['delta_tp']:>7.1f} {did_k:>6.1f} | "
              f"{a['precision_hi']:>8.3f} | {sat}")
        scan_rows.append({"k_star": k_star, "k": a["k"],
                          "L3": a, "L0": b, "did_miss": did_k})

    summary = {
        "pilot_seeds": seeds,
        "seed_offset": SEED_OFFSET,
        "excluded_from_confirmatory": True,
        "config": vars(args),
        "n_ok": len(ok),
        "n_failed": len(failed),
        "estimates": {
            "delta_L3": mean_ci(deltas, args.alpha),
            "delta_L0": mean_ci(deltas_l0, args.alpha),
            "DiD": mean_ci(dids, args.alpha),
        },
        "sizing": sizing,
        "resolution_scan": scan_rows,
    }
    with open(os.path.join(OUT_DIR, "pilot_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=float)

    sat_at_50 = next((r for r in scan_rows if r["k_star"] == 50), None)
    if sat_at_50 and sat_at_50["L3"]["sat_frac"] > 0.5:
        print(f"\n  ** D3 WARNING: at k*=50 the primary model is saturated in "
              f"{sat_at_50['L3']['sat_frac']:.0%} of replicates. A "
              f"non-inferiority test at that budget cannot fail. **")

    print(f"\nwritten to {OUT_DIR}/"
          f"{{pilot_replicates.json,pilot_summary.json,failures.csv}}")


if __name__ == "__main__":
    main()
