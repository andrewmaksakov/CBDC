# CBDC Privacy — Honest Detection Pipeline

Replaces the manuscript's §4.5 "validation" (the AUC = 1.000 definitional
artifact) with a runnable, gated, reproducible detection experiment.
Built 2026-07-07 against `DESIGN_PACK_JUL2026.md`; fixes panel-review
blockers T0-1 (no code behind the empirical claims / false
Data-Availability statement) and T0-2 (identity-aware AUC = 1.000 was a
DGP artifact: launderers were *defined* to hold 3–6 wallets vs 1–2, so
`num_wallets` separated the classes by construction).

## What the old paper got wrong, structurally

The old toy DGP encoded the label into a single marginal feature. Any
classifier that saw `num_wallets` hit AUC 1.000, and "watchlist adds
zero marginal value (1.00 → 1.00)" was arithmetically forced. Here:

* **Wallet counts come from one shared distribution for both classes**
  (`dgp.py`, the `wallet_counts` line). Laundering is a latent
  multi-step behavior — placement → layering hops across own wallets →
  structured integration — never a single separable marginal.
* **A pre-specified degeneracy audit** (`degeneracy_audit.py`) runs
  before any headline number and hard-fails (exit ≠ 0) if ANY single
  feature reaches entity-level AUC > 0.95, or if any marginal is
  class-disjoint. Run it on the old DGP and it fails on `num_wallets`
  at 1.000; run it here and the worst feature sits ≈ 0.84–0.92 across
  seeds. ("Pre-specified", not "pre-registered": the audit was fixed in
  the design pack before any result was generated, but no public
  timestamped registration exists. A staged OSF registration is planned
  for the confirmatory protocol — see `grok-frontiers-review/`.)

## Pipeline

| file | role |
|---|---|
| `dgp.py` | seeded synthetic CBDC transaction generator; `default_config()` + `surveillance_strong_config()` (the falsification world) |
| `features.py` | wallet-level (T1) and entity-level (T2–T4) features; tier column sets |
| `degeneracy_audit.py` | the gate: single-feature AUC cap 0.95 + marginal-overlap check; raises `DegeneracyError` / exits 1 |
| `detection_experiment.py` | four-tier experiment, entity-disjoint 5-fold CV, entity-clustered bootstrap CIs, label-permutation negative control |
| `equivalence_test.py` | TOST for T2 ≈ T4 (and T2 ≈ T3), paired entity-level bootstrap, margin δ = 0.03 default |
| `data_loaders.py` | the standard data interface + documented AMLworld / Elliptic adapter stubs |
| `run_all.py` | driver; regenerates every number in `results/` |
| `test_pipeline.py` | regression tests: the audit hard-fails on a reconstruction of the original num_wallets artifact, and passes (num_wallets AUC ≈ 0.5) on the shipped DGP |

**Tiers** (design pack §3): T1 structure-only on unlinked pseudonyms →
T2 + pseudonymous linkage → T3 + selected KYC/contextual attributes →
T4 + watchlist bit. The tested claim is the **non-inferiority** of T2 to
T4 — that withholding the auxiliary block costs at most a tolerated
amount of detection — not two-sided equivalence, and not a claim about
access to raw civil identity. T3/T4 expose `kyc_tier`,
`account_age_days`, `prior_sar_count`, `jurisdiction_risk` and an
`on_watchlist` bit; they do not expose names, government IDs, or a full
KYC dossier. No claim is made here that any particular cryptographic
construction achieves T2: linkage mechanism selection is pending
co-author engineering review (`grok-frontiers-review/02-dlt-architecture-selection.md`).

**Inference honesty:** folds split on entities (never wallets/tx), the
effective N reported is the entity count, and every CI comes from an
entity-clustered bootstrap. T1's classifier scores wallets without
linkage; entity scores are max-aggregated only at evaluation.

**Model note:** design called for RandomForest/XGBoost/GNN. This build
uses `LogisticRegression` + `HistGradientBoostingClassifier` (sklearn's
gradient boosting — XGBoost is not installed here; same model family).
A GNN tier is deliberately deferred to the real-data run (PyTorch
Geometric on the ROCm box) — it changes nothing about the harness.

## Reproduce

```bash
cd detection/
python3 run_all.py                     # default: seed 20260707, 8000 entities, δ=0.03
python3 run_all.py --seed 42           # any seed; all numbers regenerate
python3 degeneracy_audit.py [seed]     # gate only
```

Environment: pinned in `requirements.txt` (Python 3.14, numpy 2.3.5,
scipy 1.16.3, scikit-learn 1.8.0, pandas 2.3.3). Runtime ≈ 30 s. Every random
draw flows from the single `--seed` (DGP, folds, models, bootstraps) — but
seeding alone is not enough for *byte*-identical output: scikit-learn's
gradient-boosting implementation is not bit-stable across minor versions, so
regenerating `results/` exactly requires the pins. Under a different sklearn the
findings replicate; the CSVs will differ in the last digits.

The *Python* version is looser than the library pins: independently checked on
3.12 and 3.14 with the pinned libraries, `results_*.csv`, `summary.json`,
`degeneracy_audit_*.json` and every `tost_*.json` match exactly. Only the raw
per-entity out-of-fold logit scores in `oof_*.csv` drift, at 1e-9--1e-14, which
reaches no reported figure.

Outputs in `results/`: `results_{world}.csv` (AUC/AP + 95% clustered CIs
per tier per model), `oof_{world}.csv` (per-entity out-of-fold scores —
the TOST input), `degeneracy_audit_{world}.json`,
`tost_{world}_*.json`, `summary.json`.

## Reference results (seed 20260707, 8000 entities, 388 launderers)

Scaled from 800 to 8000 on 24 Jul: at 800 entities only ~29 launderers
survive, at which the tiers are not separately identified and every
verdict is underpowered. All numbers below trace to `results/summary.json`.

Default world, entity-level:

| model | metric | T1 | T2 | T3 | T4 |
|---|---|---|---|---|---|
| gboost | AUC | 0.9871 | 0.9977 | 0.9979 | 0.9986 |
| gboost | AP | 0.9119 | 0.9805 | 0.9806 | 0.9849 |
| logit | AUC | 0.9653 | 0.9812 | 0.9873 | 0.9921 |
| logit | AP | 0.8507 | 0.8593 | 0.8943 | 0.9218 |

TOST T2 vs T4 at δ = 0.03, with `equiv_bound` = the smallest margin at
which the comparison would read EQUIVALENT:

| model | metric | Δ | 90% CI | equiv_bound | verdict |
|---|---|---|---|---|---|
| gboost | AUC | +0.0009 | [−0.0002, +0.0021] | 0.0021 | EQUIVALENT |
| gboost | AP | +0.0044 | [−0.0008, +0.0102] | 0.0102 | EQUIVALENT |
| logit | AUC | +0.0109 | [+0.0070, +0.0149] | 0.0149 | EQUIVALENT |
| logit | AP | **+0.0625** | [+0.0478, +0.0781] | 0.0781 | **SURVEILLANCE_SUPERIOR** |

**The metric matters more than the margin.** gboost AUC saturates at
0.998, so an equivalence verdict there is close to automatic and carries
little information. AP retains resolution under 4.9% prevalence and
flips the logit verdict: the linear model gains materially from identity
and watchlist access, the boosted model does not. Read `equiv_bound`
rather than the verdict — the AP δ = 0.03 is inherited from the AUC
convention and is not operationally derived. Deriving an operational
margin is the first item of the Aug-2026 confirmatory protocol.

Linkage (T1 → T2), not identity (T2 → T4), carries most of the gboost
gain: AP +0.069 vs +0.004. Entity linkage is itself a surveillance
capability, which the paper says explicitly. Degeneracy gates pass with
worst single feature `w_frac_fast_mean` at 0.840; label-permutation
control 0.5129. Nothing saturates at 1.000.

That it could have come out otherwise is demonstrated, not asserted.
`surveillance_strong` (launderers behaviorally hidden, identity
attributes genuinely informative, every marginal still audit-clean)
returns **SURVEILLANCE_SUPERIOR on all four AP comparisons** — logit
T2→T4 ΔAP +0.4366, gboost +0.1446 — while the two gboost AUC verdicts
come back INCONCLUSIVE, again from saturation. `run_all.py` exits
non-zero if this world ever comes back all-EQUIVALENT: a rigged-harness
self-check.

⚠️ **These are development results, not confirmatory ones.** The Aug-2026
prospective protocol (`grok-frontiers-review/01-prospective-protocol-v3.md`
plus its statistical erratum) designates seed 20260707 pilot-only and
replaces this endpoint with missed illicit entities at a fixed alert
budget, estimated on independently generated train/test populations. Do
not quote the table above as a confirmatory finding.

## What this does and does not license

These are **synthetic** results demonstrating the harness. They make the
Data-Availability statement true for the *pipeline*, and they show the
old AUC = 1.000 is unreproducible under a non-rigged DGP. They do NOT
yet support the paper's headline claim on realistic laundering typologies
— that requires the real-data runs below. Until those are done, §4.5
must be framed as "illustrative synthetic validation of the harness",
not as evidence.

## Plugging in real data (MF / Maksakov)

1. **AMLworld (primary; Altman et al. 2023, NeurIPS).** Download
   HI-Small from Kaggle (link in `data_loaders.py`). Implement the
   column mapping in `load_amlworld()` — the docstring specifies it
   field by field. Identity/watchlist axes don't exist there: fill
   zeros and report T3/T4 as not-evaluable, or attach synthetic
   identity layers and label them as such.
2. **Elliptic (cross-check; Weber et al. 2019).** Download from Kaggle
   (link in `load_elliptic()`). Entity linkage must be proxied via
   co-spend clustering; use temporal (past→future) splits instead of
   entity folds; drop 'unknown' labels. Only the T1 → T2 step is
   evaluable.
3. Run the same three commands. The degeneracy audit runs on real data
   too — if a real dataset has a >0.95 single-feature separator, you
   want to know before quoting an AUC.
4. Fix δ before looking at real-data results, and derive it from
   operational loss (missed illicit entities at a fixed review budget)
   rather than inheriting the AUC convention. δ = 0.03 is the legacy
   working default and is **not** operationally justified.
5. The PET-AML latency sim (`../andrew-cbdc/pet_aml_sim.py`) is a
   separate artifact with two open bugs (escalation ordering, rejection
   calibration — design pack §4.5); it validates the performance
   envelope, not detection.
