"""Confirmatory run. Refuses to start without a signed protocol lock.

Protocol v3 sections 5-6 with erratum E1-E3. This is the only script that
produces numbers the manuscript may call confirmatory, and it is deliberately
hard to run by accident:

  * it loads `protocol_lock.json` and validates the signatures, the hash, the
    seed disjointness and the alert budget before generating anything;
  * it takes no statistical arguments -- every constant comes from the lock, so
    there is no flag that quietly changes a result;
  * it writes the lock hash into the output, so a table can always be traced
    to the freeze it was produced under;
  * failed replicates are logged and counted, never redrawn.

    Running this burns the pre-specification. There is one clean confirmatory
    run per freeze. If you want to explore, use pilot.py on burned seeds.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
           "NUMEXPR_NUM_THREADS"):
    os.environ.setdefault(_v, "1")

from concurrent.futures import ProcessPoolExecutor, as_completed  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import protocol_lock as pl  # noqa: E402
from inference import NON_INFERIOR, gated_did, non_inferiority  # noqa: E402
from replicate import CONTRAST_MODEL, PRIMARY_MODEL, run_replicate  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "results")


def _job(a):
    i, seed, kw, off = a
    return run_replicate(i, seed, seed + off, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", default=os.path.join(HERE, pl.LOCK_NAME))
    ap.add_argument("--workers", type=int,
                    default=max(1, (os.cpu_count() or 4) - 2))
    ap.add_argument("--dry-run", action="store_true",
                    help="validate the lock and print the plan; generate nothing")
    args = ap.parse_args()

    try:
        lock = pl.load(args.lock)
        pl.validate(lock)
    except pl.LockError as e:
        print(f"REFUSING TO RUN\n\n{e}", file=sys.stderr)
        sys.exit(2)

    seeds = pl.conf_seeds(lock)
    kw = dict(n_train=lock["D2_n_train"], n_test=lock["D1_n_test"],
              k_star=lock["D3_k_star"])
    off = lock["seed_offset"]
    delta_star = lock.get("D4_delta_star")
    alpha = lock["D9_alpha"]

    print(f"confirmatory run under lock {lock['lock_sha256'][:12]}")
    print(f"  signed by : {', '.join(s['name'] for s in lock['signatures'])}")
    print(f"  R         : {lock['R']}   seeds {seeds[0]}..{seeds[-1]}")
    print(f"  k*        : {lock['D3_k_star']}/10k on n_test={lock['D1_n_test']}")
    print(f"  delta*    : {delta_star if delta_star is not None else 'UNSET -> estimate reported, no binary verdict'}")
    print(f"  H2        : {'confirmatory' if lock['D15_h2_confirmatory'] else 'descriptive'}")
    if args.dry_run:
        print("\ndry run: lock valid, nothing generated")
        return

    records = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(_job, (i, s, kw, off)) for i, s in enumerate(seeds)]
        for done, fut in enumerate(as_completed(futs), 1):
            rec = fut.result()
            records.append(rec)
            d = rec.get(f"delta_miss_T2_minus_T4_{PRIMARY_MODEL}")
            print(f"  [{done}/{len(seeds)}] rep {rec['replicate_id']:>4} "
                  f"{rec['status']:<11} "
                  f"delta_L3={'n/a' if d is None else f'{d:+.1f}'}", flush=True)

    records.sort(key=lambda r: r["replicate_id"])
    ok = [r for r in records if r["status"] == "OK"]
    failed = [r for r in records if r["status"] != "OK"]

    with open(os.path.join(OUT_DIR, "confirmatory_failures.csv"), "w",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["replicate_id", "train_seed", "test_seed", "status", "error"])
        for r in failed:
            w.writerow([r["replicate_id"], r["train_seed"], r["test_seed"],
                        r["status"], r.get("error", "")])

    fail_rate = len(failed) / max(1, len(records))
    print(f"\n{len(ok)}/{len(records)} OK, {len(failed)} failed "
          f"({fail_rate:.1%}) -- logged, not redrawn")
    if fail_rate > 0.10:
        print("  ** failure rate above the 10% threshold (protocol 6.3): STOP, "
              "diagnose the generator, amend the protocol before continuing **")
    if not ok:
        sys.exit("no successful replicates")

    deltas = [r[f"delta_miss_T2_minus_T4_{PRIMARY_MODEL}"] for r in ok]
    deltas_l0 = [r[f"delta_miss_T2_minus_T4_{CONTRAST_MODEL}"] for r in ok]
    dids = [r["DiD_L0_minus_L3"] for r in ok]

    # H1. With delta* unset the estimate is the result; a binary verdict is
    # not manufactured from a tolerance nobody argued for.
    if delta_star is None:
        from inference import mean_ci
        h1 = mean_ci(deltas, alpha)
        h1["verdict"] = "ESTIMATE_ONLY"
        h1["note"] = ("delta* deliberately unset: reporting the operational "
                      "cost with its interval rather than a non-inferiority "
                      "verdict contingent on an unargued tolerance")
        gate = NON_INFERIOR  # H2 not blocked by an undeclared tolerance
    else:
        h1 = non_inferiority(deltas, delta_star, alpha)
        gate = h1["verdict"]

    h2 = gated_did(dids, gate, alpha)
    from inference import mean_ci
    h3 = mean_ci(deltas_l0, alpha)

    out = {
        "lock_sha256": lock["lock_sha256"],
        "lock": lock,
        "R_planned": lock["R"], "R_ok": len(ok), "R_failed": len(failed),
        "failure_rate": fail_rate,
        "H1_delta_miss_L3": h1,
        "H2_DiD": h2,
        "H3_delta_miss_L0_descriptive": h3,
        "replicates": records,
    }
    with open(os.path.join(OUT_DIR, "confirmatory_summary.json"), "w") as f:
        json.dump(out, f, indent=2, default=float)

    print(f"\n=== H1 (primary, L3) ===")
    print(f"  mean delta_miss = {h1['mean']:+.3f}  90% CI "
          f"[{h1['ci_lo']:+.3f}, {h1['ci_hi']:+.3f}]   verdict {h1['verdict']}")
    if h1.get("degenerate"):
        print(f"  ** {h1['degenerate_note']} **")
    print(f"\n=== H2 (DiD, {'confirmatory' if h2.get('confirmatory') else 'DESCRIPTIVE'}) ===")
    print(f"  mean DiD = {h2['mean']:+.3f}  90% CI "
          f"[{h2['ci_lo']:+.3f}, {h2['ci_hi']:+.3f}]   {h2.get('status')}")
    if h2.get("note"):
        print(f"  note: {h2['note']}")
    print(f"\n=== H3 (L0, descriptive) ===")
    print(f"  mean delta_miss = {h3['mean']:+.3f}  90% CI "
          f"[{h3['ci_lo']:+.3f}, {h3['ci_hi']:+.3f}]")
    print(f"\nwritten to {OUT_DIR}/confirmatory_summary.json")


if __name__ == "__main__":
    main()
