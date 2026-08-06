# Confirmatory pipeline (protocol v3 + statistical erratum)

Implements the prospective design in `grok-frontiers-review/01-prospective-protocol-v3.md`
as corrected by `01-prospective-protocol-v3-STATISTICAL-ERRATUM.md`.

**Status: pilot only. No confirmatory run has been made, and none should be until
the author decision table is signed.** The decision table is unsigned as of
6 Aug 2026, so `k*`, `δ*`, `τ` and `α` here are provisional defaults for design
work — not scientific constants.

## Why this exists separately from `../run_all.py`

The pilot pipeline (`../`) answers "is the ranking good" via AUC/AP on
concatenated out-of-fold scores. The confirmatory design answers a different
question — "how many illicit entities go unreviewed at a fixed alert budget" —
on independently generated train and test populations. Protocol v3 §4.2 forbids
the OOF path for confirmatory claims, so this is a parallel pipeline rather
than a flag on the old one. The old results become a **pilot**, not a finding.

| file | role |
|---|---|
| `endpoint.py` | alert selection, `MissedPer10k`, paired Δ, DiD, resolution scan |
| `test_endpoint.py` | 11 tests pinning the sign conventions and the ceiling behaviour |
| `replicate.py` | one replicate: two independent worlds, gate, fit×score, endpoints |
| `inference.py` | Student-*t* CI for the replicate mean, non-inferiority, H1→H2 gate, pilot sizing |
| `pilot.py` | excluded Monte-Carlo pilot: sizes R **and** maps where the endpoint resolves |

## The ceiling problem

`MissedPer10k` at a fixed budget saturates from the opposite side to AUC. If the
budget is small enough that every arm achieves precision 1.0 in its top *k*,
then TP = *k* for all tiers, Δ ≡ 0, and the non-inferiority test returns
**PASS with no data able to contradict it**.

Decision-table D3 proposes k\* = 50 per 10,000. On the existing pilot scores and
on a fresh train/test pilot, that budget is saturated in **100%** of replicates
for the primary model. A confirmatory run frozen there would reproduce the
structure of the AUC = 1.000 artifact this pipeline was built to retract — a
verdict guaranteed by the operating point rather than measured.

Worse, under erratum E2 the vacuous H1 pass *opens* the H2 gate, where DiD is
also identically zero; H2 then fails, and E2's own rule requires dropping the
"model capacity conditions the value of identity access" headline. **Freezing
D3 at 50 would force abandonment of the paper's central claim on an artifact.**

`pilot.py` prints a resolution scan and warns explicitly when k\* is saturated.
Pick k\* from that scan, on pilot seeds, *before* freezing — never from
confirmatory data.

## Seeds

`PILOT_SEEDS` = 900001… and are **burned**: excluded from confirmatory analysis
permanently (protocol §6.1 step 3). `SEED_OFFSET` = 10,000,003 separates the
test stream from the training stream within a replicate.

Failures (`FAIL_AUDIT` / `FAIL_LABEL` / `FAIL_NUM`) are logged to
`results/failures.csv` and counted. **Seeds are never redrawn** — replacing a
failed seed conditions the analysis set on the generator behaving, biasing
toward worlds where the gate happens to pass.

## Run

```bash
python3 test_endpoint.py                       # semantics first
python3 pilot.py --replicates 20               # full excluded pilot
python3 pilot.py --replicates 4 --n-train 2000 --n-test 2500   # smoke
```

Replicates are independent and run across cores (`--workers`, default
cores − 2). Compute is not the binding constraint: the entity-level bootstraps
that dominated the old runtime are gone, because inference is now over
replicates rather than over entities.

## Not built yet

- **T2-resolved** entity resolution (noisy merges/splits), cluster-level alert
  budget, and the dual optimistic/conservative scoring of erratum E5. This is
  the largest remaining piece and is P1 — H1/H2 are defined on T2-oracle.
- `protocol_lock.json` writer. Blocked on the decision table being signed;
  writing a lock file from unsigned values would give provisional numbers the
  appearance of a freeze.
- Confirmatory driver. Deliberately absent until the lock exists — there is no
  safe way to "just try" a confirmatory run without burning the pre-specification.
- T1 tier. Protocol §4.3 admits it only as an evaluation benchmark
  (max-pooling wallets through the *true* entity map is oracle information, not
  an operational unlinked detector), so it is out of the confirmatory family.
- External data (AMLworld/Elliptic) — loaders still raise `NotImplementedError`,
  and they cannot validate T3/T4 in any case.
