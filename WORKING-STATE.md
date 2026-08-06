# Where the CBDC paper is — 23 July 2026

Andrew: this branch is the current working state, so you can see what moved since we last sat
down with it in February. `main` carries the stable pieces (corrected bibliography, the
`detection/` pipeline); this branch carries the manuscript those pieces belong to.

```bash
git clone https://github.com/andrewmaksakov/CBDC.git
cd CBDC && git checkout jul2026-working
```

## What's on this branch that isn't on main

| File | What it is |
|---|---|
| `main.tex` | current manuscript — 37pp, compiles clean, 0 undefined citations |
| `main.pdf` | compiled 21 Jul, so you don't have to build it to read it |
| `CHANGES-FOR-ANDREW.md` | the 21 Jul positioning pass, 18 numbered items, before → after |
| `FORWARD_NOTE.md` | why the bibliography was replaced wholesale and why `detection/` exists |

## The short version of February → July

**Three things happened, in this order.**

1. **A panel review on 3 July found the empirical spine broken.** Two blockers. (T0-1) The
   Data-Availability statement pointed at this repo for the §4.5 detection code, and the code
   didn't exist — `pet_aml_sim.py` is a latency/throughput sim that never trains a classifier,
   so none of the ~10 statistics in §4.5 traced to anything runnable. (T0-2) The AUC = 1.000
   result was a data-generating artifact: launderers were *defined* to hold 3–6 wallets against
   legit users' 1–2, with no overlap, so `num_wallets` separated the classes perfectly by
   construction and "watchlist adds zero marginal value (1.00 → 1.00)" was arithmetically
   forced — you can't improve on a saturated ceiling.

2. **`detection/` was built on 7 July as the honest replacement** (now on `main`). Wallet counts
   are drawn from one shared distribution for both classes; laundering is a latent multi-step
   behaviour rather than a single separable marginal. A pre-registered degeneracy audit runs
   before any headline number and hard-fails if any single feature reaches entity-level
   AUC > 0.95 — point it at the old DGP and it fails on `num_wallets` at 1.000. Four nested
   tiers (T1 structure-only → T2 + pseudonymous linkage → T3 + identity → T4 + watchlist), so
   each surveillance increment is priced separately, with entity-disjoint folds and
   entity-clustered bootstrap CIs.

   The result, on synthetic data, is a weaker but real version of the paper's thesis: most of
   the marginal value sits in the **linkage** step (T1 → T2), and T2 ≈ T4 comes out EQUIVALENT
   under TOST for the gradient-boosted model and INCONCLUSIVE for the logit — identity adds a
   little that a linear model can't recover from behaviour alone. Reported, not buried. And the
   harness can come out the other way: the `surveillance_strong` world returns
   SURVEILLANCE_SUPERIOR, and `run_all.py` exits non-zero if it ever doesn't. These are
   synthetic results demonstrating the harness, not evidence for the headline claim — that needs
   the AMLworld / Elliptic runs (adapters stubbed in `data_loaders.py`).

3. **A positioning pass on 21 July fixed the frame.** The §2.4 gap claim ("limited analysis of
   CBDC architectures that achieve security through mechanism design rather than surveillance")
   was false — there's a 30-year cryptographic-compliance lineage (Camenisch–Maurer–Stadler
   trustee e-cash 1996 → Compact E-Cash → GGM16 → Platypus and PEReDi at CCS '22 → Privacy
   Pools) plus live BIS programmes (Aurora, Hertha) doing privacy-preserving AML at scale. The
   paper now cites the lineage and stakes its novelty on what survives contact with it: the
   **identity-axis decomposition** (Aurora and Hertha both ablate the *data-sharing* axis;
   neither ablates the *identity* axis — that's the experiment this paper runs), the
   **abandonment primitive**, and the policy-bridge synthesis. Two honest limitations were added
   (abandonment doubles as a free adversarial probing oracle; anonymous notification is
   prohibited tipping-off under FATF R.21 / POCA s.333A), and the "game-theoretic" label came
   off a section containing no formal game theory. Your §5.4 was not touched. Details:
   `CHANGES-FOR-ANDREW.md`.

## What's still open

**Murad's:**
- **§4.5 rewrite** around the `detection/` results. Everything downstream is frozen until this
  lands: the abstract's 87–95% headline, §6.5's 5–13% figures, §8.3's first paragraph. Those
  numbers are still the old ones in the `main.tex` on this branch.
- The 73% figure attributed to `OxfordCBDCSurvey2025` is still unverified against the source.
- MDPI *FinTech* template conversion (target: regular track, mid-September).
- Zenodo re-deposit — the live record is the January v1.1.0 and predates your §5.4 merge.

**Yours, if you want them:**
- **`pet_aml_sim.py` escalation-ordering bug.** `risk_tier` is read inside the transaction loop
  (travel-rule check and escalation, ~lines 468/475) but only assigned by `run_batch` risk
  propagation *after* the loop finishes. Tier-based escalation therefore can never fire, and the
  "zero escalations" result is guaranteed by construction rather than by the architecture. §5.4.3
  has been reworded to say precisely that in the interim; a fix plus a seeded rerun would let
  Table 3 carry a real escalation number instead.
- The **36.8% rejection rate** is worth a calibration look while you're in there.
- Anything in `CHANGES-FOR-ANDREW.md` you want reverted or rephrased — say so before the MDPI
  reformat, after which it gets expensive.

## Sanity check before you trust any of it

```bash
cd detection/ && python3 run_all.py
```

≈40 seconds. It should regenerate `results/` byte-identically to what's committed. If it
doesn't, the environment differs (Python 3.14, numpy 2.3.5, scipy 1.16.3, sklearn 1.8.0,
pandas 2.3.3 here) and we need to know that before either of us quotes a number.
