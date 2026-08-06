# CBDC repo fix bundle — what to merge and why

**To:** Andrew Maksakov
**Repo:** github.com/andrewmaksakov/CBDC
**Bundle assembled:** 21 July 2026 (from `cbdc-privacy/` local canon)

## What's in this bundle

1. `references.bib` — the corrected bibliography (replaces the repo's copy wholesale)
2. `detection/` — the Section 4.5 detection-simulation validation pipeline (code, README, seeded results)

## Why the bib replacement (item 1)

The `references.bib` currently in the repo (HEAD `2b177db`, February) carries **five fabricated
author sets** that were corrected locally but never propagated to the public surface:

| Key | Repo (wrong) | Corrected (verified against live source) |
|-----|--------------|------------------------------------------|
| `OfflineCBDC2024` | "Seres, Istvan Andras and others" | Michalopoulos et al. |
| `ZKPSurvey2025` | "R, Anitha and others" | Shashidhara et al. |
| `UFLaw2024` | "Golumbia, David and others" | Jiang |
| `OxfordCBDCSurvey2025` | "Chen, Karen and others" | Plato-Shinar, Maman, Shema Zaltokrilov, Yaacobi |
| `Koti2024Graphiti` | seven invented names ("Nishanth Koti, Parth Kukkala, Ajith Patra, ...") | **Nishat Koti, Varsha Bhat Kukkala, Arpita Patra, Bhavish Raj Gopal** (IACR ePrint 2024/1756, fetched 21 Jul; also published at ACM CCS 2024) |

Also in this copy (all verified against Crossref/IACR/publisher on 21 Jul):

- `Campanelli2017` renamed to `Campanelli2019` (LegoSNARK is CCS 2019; cite sites in main.tex updated)
- `Wang2025UnbalancedPSI` title aligned to the published PoPETs form, "Unbalanced PSI from Client-Independent Relaxed Oblivious PRF" (Crossref 10.56553/popets-2025-0109)
- `choi2025cbdcprivacy` completed with IER 66(2), 823–847; its BIS working-paper twin `BIS2024Privacy` is no longer cited in the manuscript (same Choi/Kim/Kim/Kwon survey — was double-cited as two independent sources; entry retained in the bib with a note)
- `ECBConsultation2021` note corrected: the consultation had 8,221 responses and privacy was **ranked the most important feature by 43% of respondents** (the old "41% focused on privacy" claim doesn't match the ECB's own report)
- **Eight entries appended 21 Jul (positioning pass, all verified against Crossref/IACR/ACM/BIS the same day):** `CamenischMaurerStadler1996`, `Camenisch2005CompactEcash`, `Garman2016Accountable`, `Wuest2022Platypus`, `Kiayias2022PEReDi`, `Buterin2024PrivacyPools`, `BISAurora2023`, `BISHertha2025`. These back the repositioned Sections 2.2--2.4 (the cryptographic-compliance lineage and the BIS AML programs the paper now engages; see `CHANGES-FOR-ANDREW.md` in the paper folder). The bundle bib includes them so it remains a wholesale replacement for the repo copy.

A bibliography with invented author names is the kind of thing that sinks a submission on
integrity grounds regardless of content — this needs to reach the public repo before anyone
follows the paper's pointer to it.

## Why `detection/` (item 2)

The paper's Data-Availability statement and Section 8.3 point readers to the repo for the
Section 4.5 detection-simulation code. The repo currently has only `pet_aml_sim.py` (the
Section 5.4 latency/throughput stack sim — no classifier, no AUC code), so the availability
claim is false until `detection/` lands. The manuscript has been reworded in the interim to
say the detection code "is included in the submission supplement and will be merged into the
public repository" — merging this directory is what makes that sentence permanently true.

The pipeline is self-contained: `run_all.py` (seeded, seed 20260707), `test_pipeline.py`
(regression tests incl. a degeneracy audit that hard-fails on the old `num_wallets` artifact),
and `results/` with the committed CSVs/JSONs the README numbers trace to. Exclude nothing;
`__pycache__` is already stripped.

## What NOT to merge yet

- **`main.tex`** — the repo copy is the stale February version, but don't overwrite it with the
  current local one either: the Section 4.5 empirical story is being rewritten around the
  detection pipeline results (Murad is steering that). Repo main.tex gets replaced when the
  rewrite lands.

## Heads-up on your sim (separate from this bundle)

`pet_aml_sim.py` has an ordering bug worth fixing before the next run: `risk_tier` is read
inside the transaction loop (travel-rule check and escalation, ~lines 468/475) but only
assigned by `run_batch` risk propagation **after** the loop completes — so tier-based
escalation can never fire and "zero escalations" is guaranteed by construction, not by the
architecture. The paper's §5.4.3 interpretation has been reworded to say exactly that. A fix +
seeded rerun (and a look at the 36.8% rejection-rate calibration) would let Table 3 and §5.4.3
carry an honest escalation number. Your artifact, your sign-off — happy to talk through it.

## Merge commands (from a clone of the repo)

```bash
cp /path/to/repo-fix-bundle/references.bib references.bib
rsync -a /path/to/repo-fix-bundle/detection/ detection/
git add references.bib detection
git commit -m "Fix fabricated author sets in references.bib; add Section 4.5 detection validation pipeline"
git push origin main
```
