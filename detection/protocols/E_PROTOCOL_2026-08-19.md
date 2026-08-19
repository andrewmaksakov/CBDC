# Prospective protocol — capacity ladder and DGP surface (E1–E6)

**Dated:** 19 August 2026 (frozen at the commit introducing this file; the commit hash is the
timestamp of record).
**Scope:** the empirical expansion for the Frontiers in Blockchain revision of the CBDC
privacy paper (DAI-2511), packages E1–E6 of `FRONTIERS_BLOCKCHAIN_SUBMISSION_PLAN_AUG2026.md`
(kept off-repo; summarised here so this document is self-contained).
**Relationship to prior work:** the 6 August 2026 confirmatory run (lock `160e9a7762879f76`,
52/52 replicates) is complete and untouched. Nothing here reopens it. This protocol governs the
NEW runs only.
**Status vocabulary:** constants below are FROZEN unless listed in §8 (pilot-adjustable
feasibility knobs). Feasibility knobs may change once, after the pilot, before the frozen
runs, and every change is recorded as a dated amendment in this file. Nothing changes after
the first frozen-run seed is consumed.

## 1. Estimands

All estimands are entity-level, computed per (world, model, replicate), then aggregated as
specified in §6.

- **ΔL (linkage increment):** M(T2) − M(T1)
- **ΔI (identity increment):** M(T3) − M(T2)
- **ΔW (watchlist increment):** M(T4) − M(T3)
- **ΔF (full-access increment):** M(T4) − M(T2)  ← primary
- **Capacity interaction:** ΔF(model m) − ΔF(model m′) for ladder pairs (m, m′); the headline
  contrast is ΔF(linear) − ΔF(boosted).
- **Surface map:** ΔF as a function of (behavioral recoverability, identity signal), per model.

## 2. Metrics

- **Primary:** average precision (AP), entity level.
- **Co-primary (operational):** recall at a fixed alert budget of 5% of monitored entities
  (k = 500 per 10,000), matching the 6 August confirmatory endpoint. Missed-illicit-per-10,000
  is reported alongside as its complement in count units.
- **Secondary:** AUC (continuity with prior results); precision at the same budget.
- **No binary equivalence verdicts.** Per the 6 August decision (D4_delta_star = None), we
  report estimates with uncertainty, not non-inferiority verdicts. The tolerance-setting
  history (post-pilot, pre-confirmatory) is disclosed in the manuscript.

## 3. E1 — model capacity ladder

Four capacity levels, all scikit-learn, identical tuning discipline:

| Rung | Model | Capacity property |
|---|---|---|
| M1 | Logistic regression (L2, `saga`, standardized features) | linear |
| M2 | `HistGradientBoostingClassifier` with `interaction_cst="no_interactions"` | additive nonlinear (no feature interactions) |
| M3 | `RandomForestClassifier` | bagged interactions |
| M4 | `HistGradientBoostingClassifier` (unconstrained) | boosted interactions |

Capacity is thus varied along two named axes (nonlinearity: M1→M2; interactions: M2→M3/M4),
not by brand name. No graph model: the manuscript makes no graph-capability claim beyond
tabular linkage aggregates.

**Tuning:** one shared small grid per model family (≤ 6 configurations), selected by inner
3-fold entity-grouped CV on training folds only, optimizing AP. The grids are fixed in
`ladder_config.py` at the freeze commit. Every rung gets the same inner-CV budget. No
per-tier tuning: the configuration selected on T4 features is reused for all tiers within a
(world, model, replicate) — this is conservative against tier-specific overfitting and keeps
tier contrasts within-model.

## 4. E2 — mechanism ablation

On the default world only, with M1 and M4 (the reversal pair), toggle feature groups within
the T4 set in a factorial: {linkage-derived aggregates} × {identity attributes} × {watchlist
bit}, 8 cells. Attribution table reports AP per cell. Purpose: identify which group drives
the M1-vs-M4 reversal. Exploratory; reported as such.

## 5. E3/E4 — DGP surface and prevalence

Two independently parameterized axes in `dgp.py`, exposed as config scalars with the current
default reproducing today's behavior exactly (verified by regression test before any new run):

- **Behavioral recoverability** b ∈ {low, mid=current, high}: scales obfuscation noise on the
  layering/structuring signatures.
- **Identity signal** s ∈ {low, mid=current, high}: scales the class-conditional separation of
  `kyc_tier` / `prior_sar_count` / `jurisdiction_risk` and the watchlist inclusion rates. At
  s=low the identity attributes are near-uninformative by construction; the current
  class-conditioned setting is exposed as the mid regime, i.e. an experimenter choice, per the
  submission plan's DGP-conditioned-signal gap.

Grid: the full 3×3 surface runs with M1 and M4 at prevalence 3%. The default world (b=mid,
s=mid) additionally runs the full ladder (E1) and the prevalence sweep p ∈ {1%, 3%, 5%} (E4)
with M1 and M4. n = 8,000 entities per world, matching the canonical run.

## 6. E6 — replication and uncertainty

- **R = 10 independent DGP seeds per cell** (feasibility knob, §8) for surface/prevalence
  cells; **R = 20** for the default-world ladder cells.
- Within each replicate: entity-disjoint 5-fold CV as in the existing pipeline; entity-level
  scores are out-of-fold.
- Reported uncertainty: between-replicate SD and a t-interval on the replicate mean per cell
  (the confirmatory pipeline's convention); within-replicate clustered-bootstrap CIs are
  computed for the default world only (cost control) to show the two uncertainty layers
  separately.
- **Seed policy:** pilot seeds base `2026081901`, burned unconditionally. Frozen-run seeds
  base `2026081951`. All bases and offsets pass the existing `validate()` range guard
  (sklearn 2³²−1 ceiling — known failure mode, already patched in `replicate.py`).

## 7. Controls and gates (unchanged from existing pipeline)

- Degeneracy audit runs per world configuration and hard-fails the run on single-feature
  entity AUC > 0.95 or class-disjoint marginals. NOTE: at s=high the audit binding is a
  RESULT (the surface is expected to approach the retracted regime); a world excluded by the
  audit is reported as excluded-by-gate in the surface map, not silently dropped.
- Label-permutation negative control per world at R=2.
- The surveillance-favoring falsification world (`surveillance_strong_config`) reruns once
  under the ladder as a positive control: it must show material identity increments for all
  models, or the harness is under-sensitive.

## 8. Pilot-adjustable feasibility knobs

Only these may change after the pilot (once, with a dated amendment): R per cell (down to
minimum 5 / up to 20), inner-CV grid sizes (down only), inclusion of M2/M3 on surface cells
(compute permitting). The grid axes, estimands, metrics, models M1/M4, n=8,000, seed bases,
and gate thresholds are frozen now.

## 9. Interpretation discipline (fixed now, before results)

- The headline is a **conditional map**, not a universal claim: where ΔF is small for M4 and
  material for M1, the paper says exactly that, per regime.
- Unfavorable regions (identity access materially beneficial for all models) are reported
  with the same prominence as favorable ones.
- Synthetic scope is stated in the abstract's result sentence.
- External benchmarks (AMLworld/Elliptic), if run, validate T1/T2 behavior only; identity
  axes are non-evaluable there and are labelled as such (E7 is NOT governed by this protocol
  and requires its own pre-specification if promoted beyond a sanity check).

## Amendments

- **A1 (19 Aug 2026, pre-pilot):** M1 solver `saga` → `lbfgs`. Rationale: `saga` returned
  ConvergenceWarning at max_iter=5000 on the wallet-level T1 design in the smoke run; `lbfgs`
  optimizes the identical L2 objective deterministically. No result existed when this changed.
- **A2 (19 Aug 2026, post-pilot, pre-frozen):** surface and prevalence cells upgraded from
  the two-model reversal pair to the FULL four-rung ladder, under §8's "inclusion of M2/M3
  on surface cells (compute permitting)". Pilot timing: ~200 s per four-model unit — the
  full grid costs under an hour of wall time. R values unchanged at protocol defaults
  (R=20 default ladder, R=10 surface/prevalence, R=2 controls). No frozen-run seed had
  been consumed when this changed.
