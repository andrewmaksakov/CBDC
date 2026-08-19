"""Aggregate the frozen E1-E6 runs into the manuscript tables.

Reads results/ladder/frozen/*.jsonl, writes results/ladder/frozen/
summary_tables.json and prints the tables. Uncertainty is the
between-replicate t-interval on the replicate mean (the confirmatory
pipeline's convention); alpha = 0.10 (90% CI), matching the 6 Aug run.

Usage: python analyze_ladder.py
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import stats

FROZEN = Path(__file__).parent / "results" / "ladder" / "frozen"
ALPHA = 0.10


def _load(name):
    f = FROZEN / f"{name}.jsonl"
    return [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []


def _tmean_ci(xs):
    xs = np.asarray(xs, dtype=float)
    n = len(xs)
    m = float(xs.mean())
    if n < 2:
        return {"mean": m, "ci_lo": None, "ci_hi": None, "sd": None, "n": n}
    sd = float(xs.std(ddof=1))
    h = float(stats.t.ppf(1 - ALPHA / 2, n - 1) * sd / np.sqrt(n))
    return {"mean": m, "ci_lo": m - h, "ci_hi": m + h, "sd": sd, "n": n}


def _collect(records, key_fn):
    """key_fn(record) -> group key; accumulates increments and tier levels."""
    acc = defaultdict(lambda: defaultdict(list))
    for r in records:
        if r["gate"] != "pass":
            continue
        k = key_fn(r)
        for model, d in r["models"].items():
            for metric in ("ap", "recall_at_budget"):
                for inc, v in d["increments"][metric].items():
                    acc[(k, model)][f"{inc}_{metric}"].append(v)
            for tier in ("T1", "T2", "T3", "T4"):
                acc[(k, model)][f"{tier}_ap"].append(d["tiers"][tier]["ap"])
                acc[(k, model)][f"{tier}_missed_per_10k"].append(
                    d["tiers"][tier]["missed_per_10k"])
    return {k: {stat: _tmean_ci(v) for stat, v in stats_.items()}
            for k, stats_ in acc.items()}


def main():
    out = {}

    ladder = _collect(_load("default_ladder"), lambda r: "default")
    out["default_ladder"] = {f"{m}": v for (_, m), v in ladder.items()}

    surface = _collect(_load("surface"),
                       lambda r: r["label"].rsplit("|", 1)[0])
    out["surface"] = {f"{k}::{m}": v for (k, m), v in surface.items()}

    prev = _collect(_load("prevalence"),
                    lambda r: f"p={r['config']['base_rate']:g}")
    out["prevalence"] = {f"{k}::{m}": v for (k, m), v in prev.items()}

    ctrl = _collect(_load("controls"), lambda r: "surveillance_strong")
    out["controls"] = {f"{m}": v for (_, m), v in ctrl.items()}

    excluded = [r["label"] for name in
                ("default_ladder", "surface", "prevalence", "controls")
                for r in _load(name) if r["gate"] != "pass"]
    out["excluded_by_gate"] = excluded

    (FROZEN / "summary_tables.json").write_text(json.dumps(out, indent=2))

    def fmt(v):
        if v["ci_lo"] is None:
            return f"{v['mean']:+.4f} (n={v['n']})"
        return f"{v['mean']:+.4f} [{v['ci_lo']:+.4f},{v['ci_hi']:+.4f}]"

    print("== E1 default ladder (R per cell = n shown): dF on AP / recall@5% ==")
    for m in sorted(out["default_ladder"]):
        v = out["default_ladder"][m]
        print(f"  {m:12s} dF_ap={fmt(v['dF_ap'])}   "
              f"dF_rec={fmt(v['dF_recall_at_budget'])}   "
              f"T2_ap={v['T2_ap']['mean']:.4f} T4_ap={v['T4_ap']['mean']:.4f}")

    print("== E3 surface: dF on AP by (b,s) x model ==")
    for k in sorted(out["surface"]):
        print(f"  {k:28s} {fmt(out['surface'][k]['dF_ap'])}")

    print("== E4 prevalence: dF on AP ==")
    for k in sorted(out["prevalence"]):
        print(f"  {k:22s} {fmt(out['prevalence'][k]['dF_ap'])}")

    print("== E8 control (surveillance_strong): dF on AP ==")
    for m in sorted(out["controls"]):
        print(f"  {m:12s} {fmt(out['controls'][m]['dF_ap'])}")

    print("== excluded by gate ==", excluded or "none")


if __name__ == "__main__":
    main()
