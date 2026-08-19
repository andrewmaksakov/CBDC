"""E1–E6 driver (protocol §§5–8).

Usage:
    python run_ladder.py --stage pilot  --package smoke
    python run_ladder.py --stage pilot  --package default_ladder
    python run_ladder.py --stage frozen --package default_ladder
    python run_ladder.py --stage frozen --package surface
    python run_ladder.py --stage frozen --package prevalence
    python run_ladder.py --stage frozen --package controls

Seed policy (protocol §6): pilot base 2026081901 (BURNED), frozen base
2026081951. Replicate seed = base + replicate_index; each package uses a
disjoint index block so no seed is ever reused across packages.

Results: append-only JSONL under results/ladder/<stage>/<package>.jsonl,
plus a manifest with the config, git commit, and library versions.
Reruns skip (label, seed, model-set) units already present — safe resume.
"""

from __future__ import annotations

import os
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

PILOT_BASE = 2026081901
FROZEN_BASE = 2026081951
_SKLEARN_SEED_MAX = 2**32 - 1

N_ENTITIES = 8000
R_LADDER = 20
R_SURFACE = 10
R_CONTROLS = 2

# disjoint replicate-index blocks per package (seed = base + index)
_BLOCKS = {
    "smoke": (0, 1),
    "default_ladder": (100, 100 + R_LADDER),
    "surface": (200, 200 + 8 * R_SURFACE),       # 8 non-default worlds
    "prevalence": (500, 500 + 2 * R_SURFACE),    # p=0.01, p=0.03 at b=mid,s=mid
    "controls": (700, 700 + R_CONTROLS),         # surveillance_strong positive control
}


def _units(package, stage):
    """Yield (label-config-builder args, models, seed) work units."""
    from ladder_config import LADDER, SURFACE_MODELS
    from surface_configs import world_config

    base = PILOT_BASE if stage == "pilot" else FROZEN_BASE
    lo, hi = _BLOCKS[package]
    idx = iter(range(lo, hi))
    all_models = tuple(LADDER)

    if package == "smoke":
        i = next(idx)
        yield ("mid", "mid", 0.05, 800), ("M1_linear",), base + i
        return

    if package == "default_ladder":
        for _ in range(R_LADDER if stage == "frozen" else 3):
            i = next(idx)
            yield ("mid", "mid", 0.05, N_ENTITIES), all_models, base + i
        return

    # Amendment A2 (19 Aug 2026, post-pilot, pre-frozen): surface and
    # prevalence run the FULL ladder, not just the reversal pair.
    if package == "surface":
        worlds = [(b, s) for b in ("low", "mid", "high")
                  for s in ("low", "mid", "high") if (b, s) != ("mid", "mid")]
        for b, s in worlds:
            for _ in range(R_SURFACE if stage == "frozen" else 1):
                i = next(idx)
                yield (b, s, 0.05, N_ENTITIES), all_models, base + i
        return

    if package == "prevalence":
        for p in (0.01, 0.03):
            for _ in range(R_SURFACE if stage == "frozen" else 1):
                i = next(idx)
                yield ("mid", "mid", p, N_ENTITIES), all_models, base + i
        return

    if package == "controls":
        for _ in range(R_CONTROLS):
            i = next(idx)
            yield ("__surveillance_strong__", None, None, N_ENTITIES), \
                all_models, base + i
        return

    raise ValueError(package)


def _work(args):
    (wargs, models, seed) = args
    from surface_configs import world_config
    from dgp import surveillance_strong_config
    from ladder_experiment import run_replicate

    if wargs[0] == "__surveillance_strong__":
        cfg = surveillance_strong_config(seed=seed)
        cfg.n_entities = wargs[3]
        cfg.label = "surveillance_strong"
    else:
        b, s, p, n = wargs
        cfg = world_config(b, s, p, seed=seed, n_entities=n)
    t0 = time.time()
    rec = run_replicate(cfg, models, seed)
    rec["models_run"] = list(models)
    rec["wall_seconds"] = round(time.time() - t0, 1)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=("pilot", "frozen"), required=True)
    ap.add_argument("--package", choices=tuple(_BLOCKS), required=True)
    ap.add_argument("--workers", type=int, default=10)
    a = ap.parse_args()

    base = PILOT_BASE if a.stage == "pilot" else FROZEN_BASE
    assert 0 < base + max(hi for _, hi in _BLOCKS.values()) < _SKLEARN_SEED_MAX

    outdir = Path(__file__).parent / "results" / "ladder" / a.stage
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / f"{a.package}.jsonl"

    done = set()
    if outfile.exists():
        for line in outfile.read_text().splitlines():
            try:
                r = json.loads(line)
                done.add((r["label"], r["seed"], tuple(r["models_run"])))
            except Exception:
                pass

    units = [u for u in _units(a.package, a.stage)]
    manifest = {
        "stage": a.stage, "package": a.package, "seed_base": base,
        "n_units_planned": len(units),
        "git_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            cwd=Path(__file__).parent).stdout.strip(),
        "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "python": sys.version.split()[0],
    }
    try:
        import sklearn, numpy, pandas
        manifest["versions"] = {"sklearn": sklearn.__version__,
                                "numpy": numpy.__version__,
                                "pandas": pandas.__version__}
    except ImportError:
        pass
    (outdir / f"{a.package}.manifest.json").write_text(
        json.dumps(manifest, indent=2))

    todo = []
    from surface_configs import world_config  # early import error surfacing
    for u in units:
        wargs, models, seed = u
        if wargs[0] == "__surveillance_strong__":
            label = "surveillance_strong"
        else:
            label = f"b={wargs[0]}|s={wargs[1]}|p={wargs[2]:g}"
        if (label, seed, tuple(models)) in done:
            continue
        todo.append(u)
    print(f"{a.stage}/{a.package}: {len(todo)} of {len(units)} units to run",
          flush=True)

    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(_work, u): u for u in todo}
        for n, fut in enumerate(as_completed(futs), 1):
            rec = fut.result()
            with open(outfile, "a") as f:
                f.write(json.dumps(rec) + "\n")
            print(f"[{n}/{len(todo)}] {rec['label']} seed={rec['seed']} "
                  f"gate={rec['gate']} {rec['wall_seconds']}s", flush=True)
    print("done", flush=True)


if __name__ == "__main__":
    main()
