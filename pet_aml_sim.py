#!/usr/bin/env python3
"""
PET AML Stack Simulation (systems + performance model)

Simulates a CBDC-like payment flow with:
  - PSI watchlist screening (sanctions/PEP) via a screening utility
  - ZK policy proof bundle generation + ledger verification
  - Secure risk propagation (MPC batch) producing risk tiers
  - Tiered privacy, limits/velocity, travel rule receipt logic
  - Queueing delays at PSPs, screening service, and ledger

No external dependencies.

Usage:
  python pet_aml_sim.py --days 2 --tx-per-day 20000 --psps 8 --seed 7

Outputs:
  - average/percentile latencies
  - throughput and queueing utilization estimates
  - sanctions blocks / policy rejects / escalations
  - risk tier distribution
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import math
import random
import argparse
import statistics
import time as pytime


# -----------------------------
# Utilities
# -----------------------------

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def lognormal(mean: float, sigma: float, rng: random.Random) -> float:
    """
    Return lognormal with approx mean (in same units as mean).
    We parameterize by underlying normal mu, sigma_n.
    """
    mean = max(mean, 1e-9)
    sigma = max(sigma, 1e-9)
    mu = math.log(mean) - 0.5 * (sigma ** 2)
    return rng.lognormvariate(mu, sigma)

def percentile(data: List[float], p: float) -> float:
    if not data:
        return float("nan")
    xs = sorted(data)
    k = (len(xs) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return xs[int(k)]
    return xs[f] + (xs[c] - xs[f]) * (k - f)

def now_ms() -> int:
    return int(pytime.time() * 1000)


# -----------------------------
# Core policy & predicates
# -----------------------------

@dataclass
class Policy:
    """Simplified policy registry (per corridor / per tier)."""
    tier_tx_limit: Dict[int, float] = field(default_factory=lambda: {0: 50, 1: 500, 2: 5000, 3: 50000})
    tier_daily_cap: Dict[int, float] = field(default_factory=lambda: {0: 200, 1: 1500, 2: 15000, 3: 150000})

    travel_rule_threshold: float = 1000.0
    travel_rule_high_risk_tier: int = 2

    escalation_amount: float = 10000.0
    escalation_risk_tier: int = 2

    sanctions_attestation_ttl_s: float = 3600.0  # 1 hour

    def tx_limit(self, tier: int) -> float:
        return self.tier_tx_limit.get(tier, self.tier_tx_limit[max(self.tier_tx_limit.keys())])

    def daily_cap(self, tier: int) -> float:
        return self.tier_daily_cap.get(tier, self.tier_daily_cap[max(self.tier_daily_cap.keys())])


@dataclass
class ProofBundle:
    """Placeholder for a ZK policy proof bundle."""
    ok: bool
    reason: str = "OK"
    proof_size_bytes: int = 512
    verify_ms: float = 2.0
    prove_ms: float = 60.0
    policy_ver: str = "POLICY:v1"
    epoch_id: int = 0
    sanctions_attested: bool = True
    travel_rule_receipt: bool = False
    escrow_case_packet: bool = False


# -----------------------------
# Actors and state
# -----------------------------

@dataclass
class Wallet:
    wid: int
    psp_id: int
    tier: int
    is_sanctioned: bool = False
    daily_spend: float = 0.0
    daily_epoch: int = 0
    screening_valid_until: float = -1.0
    risk_tier: int = 0

@dataclass
class Transaction:
    txid: int
    t_arrival: float
    payer: int
    payee: int
    amount: float
    cross_border: bool
    payer_psp: int
    payee_psp: int


# -----------------------------
# Queueing service model
# -----------------------------

@dataclass
class Service:
    """Single-server queue model with service-time sampling."""
    name: str
    rng: random.Random
    mean_ms: float
    sigma: float
    next_free_t: float = 0.0  # seconds

    def sample_service_s(self) -> float:
        ms = lognormal(self.mean_ms, self.sigma, self.rng)
        return ms / 1000.0

    def run(self, t_in: float) -> Tuple[float, float]:
        t_start = max(t_in, self.next_free_t)
        wait = t_start - t_in
        dur = self.sample_service_s()
        t_out = t_start + dur
        self.next_free_t = t_out
        return t_out, wait


# -----------------------------
# PET AML services
# -----------------------------

@dataclass
class SanctionsScreeningService:
    """Models an unbalanced PSI sanctions screening utility."""
    svc: Service
    mean_comm_mb: float = 4.0
    comm_sigma: float = 0.25

    def screen(self, t_in: float, wallet: Wallet, policy: Policy) -> Tuple[float, float, bool, float]:
        t_out, wait = self.svc.run(t_in)
        comm_mb = lognormal(self.mean_comm_mb, self.comm_sigma, self.svc.rng)
        passed = not wallet.is_sanctioned
        if passed:
            wallet.screening_valid_until = t_out + policy.sanctions_attestation_ttl_s
        else:
            wallet.screening_valid_until = -1.0
        return t_out, wait, passed, comm_mb


@dataclass
class MPCConsortium:
    """Models secure risk propagation (batch MPC) over a transaction graph."""
    rng: random.Random
    anchor_tx: int = 200_000
    anchor_hours: float = 3.0
    decay: float = 0.35
    iters: int = 2

    def batch_runtime_hours(self, tx_count: int) -> float:
        return (tx_count / self.anchor_tx) * self.anchor_hours * (self.iters / 2.0)

    def run_batch(self, wallets: Dict[int, Wallet], edges: List[Tuple[int, int, float]]) -> Dict[int, int]:
        risk = {wid: (1.0 if w.is_sanctioned else 0.0) for wid, w in wallets.items()}
        for wid, w in wallets.items():
            if (not w.is_sanctioned) and self.rng.random() < 0.001:
                risk[wid] = max(risk[wid], 0.7)

        adj: Dict[int, List[Tuple[int, float]]] = {}
        for u, v, amt in edges:
            adj.setdefault(u, []).append((v, amt))

        norm_adj: Dict[int, List[Tuple[int, float]]] = {}
        for u, outs in adj.items():
            total = sum(amt for _, amt in outs) + 1e-9
            norm_adj[u] = [(v, amt / total) for v, amt in outs]

        for _ in range(self.iters):
            new_risk = dict(risk)
            for u, outs in norm_adj.items():
                for v, wgt in outs:
                    new_risk[v] = max(new_risk[v], risk[u] * self.decay * wgt)
            risk = new_risk

        tiers: Dict[int, int] = {}
        for wid, score in risk.items():
            if score >= 0.75:
                tiers[wid] = 3
            elif score >= 0.35:
                tiers[wid] = 2
            elif score >= 0.10:
                tiers[wid] = 1
            else:
                tiers[wid] = 0

        for wid, t in tiers.items():
            wallets[wid].risk_tier = t
        return tiers


@dataclass
class ZKProofEngine:
    """Models proof generation and verification costs."""
    prover: Service
    verifier: Service
    snark_size_bytes: int = 512
    stark_size_bytes: int = 45_000
    use_stark: bool = False

    def prove(self, t_in: float, bundle: ProofBundle) -> Tuple[float, float]:
        return self.prover.run(t_in)

    def verify(self, t_in: float, bundle: ProofBundle) -> Tuple[float, float]:
        return self.verifier.run(t_in)

    def proof_size(self) -> int:
        return self.stark_size_bytes if self.use_stark else self.snark_size_bytes


# -----------------------------
# Ledger model
# -----------------------------

@dataclass
class Ledger:
    """Verifies proof bundles and enforces policy."""
    verify_svc: Service
    policy: Policy
    seen_nullifiers: set = field(default_factory=set)

    def verify_and_settle(self, t_in: float, tx: Transaction, payer: Wallet, proof: ProofBundle,
                          nullifier: str) -> Tuple[float, float, bool, str]:
        t_out, wait = self.verify_svc.run(t_in)

        if nullifier in self.seen_nullifiers:
            return t_out, wait, False, "REPLAY_NULLIFIER"
        self.seen_nullifiers.add(nullifier)

        if not proof.sanctions_attested:
            return t_out, wait, False, "NO_SANCTIONS_ATTEST"

        if tx.amount > self.policy.tx_limit(payer.tier):
            return t_out, wait, False, "TIER_TX_LIMIT"

        if payer.daily_epoch != int(tx.t_arrival // (24 * 3600)):
            payer.daily_epoch = int(tx.t_arrival // (24 * 3600))
            payer.daily_spend = 0.0

        if payer.daily_spend + tx.amount > self.policy.daily_cap(payer.tier):
            return t_out, wait, False, "DAILY_CAP"
        payer.daily_spend += tx.amount

        tr_trigger = tx.cross_border and (
            tx.amount >= self.policy.travel_rule_threshold or payer.risk_tier >= self.policy.travel_rule_high_risk_tier
        )
        if tr_trigger and not proof.travel_rule_receipt:
            return t_out, wait, False, "TRAVEL_RULE_MISSING_RECEIPT"

        return t_out, wait, True, "OK"


# -----------------------------
# Simulation orchestrator
# -----------------------------

@dataclass
class SimConfig:
    seed: int = 7
    days: int = 1
    tx_per_day: int = 20_000
    psps: int = 8
    wallets_per_psp: int = 5_000

    cross_border_p: float = 0.25
    sanctioned_p: float = 0.002

    amt_mean: float = 120.0
    amt_sigma: float = 1.0

    structuring_p: float = 0.002

    psp_front_mean_ms: float = 4.0
    psp_front_sigma: float = 0.35

    psi_mean_ms: float = 450.0
    psi_sigma: float = 0.30

    zk_prove_mean_ms: float = 60.0
    zk_prove_sigma: float = 0.50

    ledger_verify_mean_ms: float = 2.0
    ledger_verify_sigma: float = 0.30

    tr_receipt_mean_ms: float = 20.0
    tr_receipt_sigma: float = 0.60

    use_stark: bool = False


@dataclass
class SimResults:
    latencies_ms: List[float] = field(default_factory=list)
    waits_ms: Dict[str, List[float]] = field(default_factory=lambda: {"PSP": [], "PSI": [], "PROVE": [], "TR": [], "LEDGER": []})
    comm_mb_total: float = 0.0
    proof_bytes_total: int = 0

    settled: int = 0
    rejected: int = 0
    rejected_reasons: Dict[str, int] = field(default_factory=dict)
    sanctions_blocked: int = 0
    escalations: int = 0

    risk_tier_hist: Dict[int, int] = field(default_factory=lambda: {0: 0, 1: 0, 2: 0, 3: 0})
    mpc_batch_hours: float = 0.0


class PETAMLSimulator:
    def __init__(self, cfg: SimConfig):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.policy = Policy()

        self.wallets: Dict[int, Wallet] = {}
        wid = 0
        for p in range(cfg.psps):
            for _ in range(cfg.wallets_per_psp):
                tier = self.rng.choices([0, 1, 2, 3], weights=[0.55, 0.30, 0.13, 0.02])[0]
                is_sanctioned = (self.rng.random() < cfg.sanctioned_p)
                self.wallets[wid] = Wallet(wid=wid, psp_id=p, tier=tier, is_sanctioned=is_sanctioned)
                wid += 1

        self.structurers = set()
        for w in self.wallets.values():
            if self.rng.random() < cfg.structuring_p and not w.is_sanctioned:
                self.structurers.add(w.wid)

        self.psp_front: List[Service] = [
            Service(f"PSP_{i}_front", random.Random(cfg.seed + 1000 + i), cfg.psp_front_mean_ms, cfg.psp_front_sigma)
            for i in range(cfg.psps)
        ]
        self.psi = SanctionsScreeningService(
            Service("PSI_screen", random.Random(cfg.seed + 2000), cfg.psi_mean_ms, cfg.psi_sigma)
        )
        self.zk = ZKProofEngine(
            prover=Service("ZK_prover", random.Random(cfg.seed + 3000), cfg.zk_prove_mean_ms, cfg.zk_prove_sigma),
            verifier=Service("ZK_verify_stub", random.Random(cfg.seed + 3001), 0.1, 0.1),
            use_stark=cfg.use_stark
        )
        self.tr_receipt = Service("TR_receipt", random.Random(cfg.seed + 4000), cfg.tr_receipt_mean_ms, cfg.tr_receipt_sigma)

        self.ledger = Ledger(
            verify_svc=Service("Ledger_verify", random.Random(cfg.seed + 5000), cfg.ledger_verify_mean_ms, cfg.ledger_verify_sigma),
            policy=self.policy
        )

        self.mpc = MPCConsortium(random.Random(cfg.seed + 6000))

    def generate_transactions(self) -> List[Transaction]:
        txs: List[Transaction] = []
        total_wallets = len(self.wallets)

        seconds_per_day = 24 * 3600
        txid = 0

        for day in range(self.cfg.days):
            for _ in range(self.cfg.tx_per_day):
                t_arrival = day * seconds_per_day + self.rng.random() * seconds_per_day

                payer = self.rng.randrange(total_wallets)
                if self.rng.random() < self.cfg.cross_border_p:
                    payer_psp = self.wallets[payer].psp_id
                    other_psps = [p for p in range(self.cfg.psps) if p != payer_psp]
                    payee_psp = self.rng.choice(other_psps)
                    base = payee_psp * self.cfg.wallets_per_psp
                    payee = base + self.rng.randrange(self.cfg.wallets_per_psp)
                    cross = True
                else:
                    payer_psp = self.wallets[payer].psp_id
                    payee = payer
                    while payee == payer:
                        base = payer_psp * self.cfg.wallets_per_psp
                        payee = base + self.rng.randrange(self.cfg.wallets_per_psp)
                    payee_psp = payer_psp
                    cross = False

                amt = lognormal(self.cfg.amt_mean, self.cfg.amt_sigma, self.rng)
                if payer in self.structurers:
                    amt = clamp(
                        self.policy.travel_rule_threshold * (0.6 + 0.35 * self.rng.random()),
                        5.0,
                        self.policy.travel_rule_threshold - 1.0
                    )

                txs.append(Transaction(
                    txid=txid,
                    t_arrival=t_arrival,
                    payer=payer,
                    payee=payee,
                    amount=amt,
                    cross_border=cross,
                    payer_psp=payer_psp,
                    payee_psp=payee_psp
                ))
                txid += 1

        txs.sort(key=lambda x: x.t_arrival)
        return txs

    def run(self) -> SimResults:
        res = SimResults()
        txs = self.generate_transactions()

        edges_by_day: Dict[int, List[Tuple[int, int, float]]] = {}

        for tx in txs:
            payer = self.wallets[tx.payer]

            t = tx.t_arrival
            t, wait = self.psp_front[tx.payer_psp].run(t)
            res.waits_ms["PSP"].append(wait * 1000.0)

            sanctions_pass = True
            if t > payer.screening_valid_until:
                t, w2, sanctions_pass, comm_mb = self.psi.screen(t, payer, self.policy)
                res.waits_ms["PSI"].append(w2 * 1000.0)
                res.comm_mb_total += comm_mb

            if not sanctions_pass:
                res.rejected += 1
                res.sanctions_blocked += 1
                res.rejected_reasons["SANCTIONS_HIT"] = res.rejected_reasons.get("SANCTIONS_HIT", 0) + 1
                continue

            proof = ProofBundle(ok=True)
            proof.sanctions_attested = True

            tr_trigger = tx.cross_border and (
                tx.amount >= self.policy.travel_rule_threshold or payer.risk_tier >= self.policy.travel_rule_high_risk_tier
            )
            if tr_trigger:
                t, wtr = self.tr_receipt.run(t)
                res.waits_ms["TR"].append(wtr * 1000.0)
                proof.travel_rule_receipt = True

            if (tx.amount >= self.policy.escalation_amount) or (payer.risk_tier >= self.policy.escalation_risk_tier):
                proof.escrow_case_packet = True
                res.escalations += 1

            t, w3 = self.zk.prover.run(t)
            res.waits_ms["PROVE"].append(w3 * 1000.0)
            res.proof_bytes_total += self.zk.proof_size()

            nullifier = f"{tx.payer}:{int(tx.t_arrival)}:{tx.txid}"
            t_out, w4, ok, reason = self.ledger.verify_and_settle(t, tx, payer, proof, nullifier)
            res.waits_ms["LEDGER"].append(w4 * 1000.0)

            if ok:
                res.settled += 1
                res.latencies_ms.append((t_out - tx.t_arrival) * 1000.0)
                day = int(tx.t_arrival // (24 * 3600))
                edges_by_day.setdefault(day, []).append((tx.payer, tx.payee, tx.amount))
            else:
                res.rejected += 1
                res.rejected_reasons[reason] = res.rejected_reasons.get(reason, 0) + 1

        total_batch_hours = 0.0
        for _, edges in edges_by_day.items():
            total_batch_hours += self.mpc.batch_runtime_hours(len(edges))
            self.mpc.run_batch(self.wallets, edges)

        res.mpc_batch_hours = total_batch_hours
        for w in self.wallets.values():
            res.risk_tier_hist[w.risk_tier] = res.risk_tier_hist.get(w.risk_tier, 0) + 1

        return res


def summarize(res: SimResults, cfg: SimConfig) -> None:
    total = cfg.days * cfg.tx_per_day
    print("\\n=== PET AML Stack Simulation Summary ===")
    print(f"Transactions generated:      {total:,}")
    print(f"Settled:                     {res.settled:,}")
    print(f"Rejected:                    {res.rejected:,}")
    print(f"  - Sanctions blocked:       {res.sanctions_blocked:,}")
    print(f"Escalations (case packets):  {res.escalations:,}")
    print(f"Total PSI comm (MB):         {res.comm_mb_total:,.2f}")
    print(f"Total proof bytes:           {res.proof_bytes_total:,.0f} bytes")
    print(f"Estimated MPC batch runtime: {res.mpc_batch_hours:,.2f} hours (aggregate)")

    if res.latencies_ms:
        lat = res.latencies_ms
        print("\\nLatency (ms) for settled tx:")
        print(f"  mean: {statistics.mean(lat):.2f}")
        print(f"  p50 : {percentile(lat, 0.50):.2f}")
        print(f"  p90 : {percentile(lat, 0.90):.2f}")
        print(f"  p99 : {percentile(lat, 0.99):.2f}")

    print("\\nQueue waits (ms):")
    for k, xs in res.waits_ms.items():
        if xs:
            print(f"  {k:6s} mean={statistics.mean(xs):.2f} p90={percentile(xs,0.90):.2f} p99={percentile(xs,0.99):.2f}")
        else:
            print(f"  {k:6s} (none)")

    if res.rejected_reasons:
        print("\\nTop rejection reasons:")
        for reason, c in sorted(res.rejected_reasons.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {reason:28s} {c:,}")

    print("\\nRisk tier distribution (end of sim):")
    total_wallets = cfg.psps * cfg.wallets_per_psp
    for t in sorted(res.risk_tier_hist.keys()):
        c = res.risk_tier_hist[t]
        print(f"  tier {t}: {c:,} ({100.0*c/total_wallets:.2f}%)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--tx-per-day", type=int, default=20_000)
    ap.add_argument("--psps", type=int, default=8)
    ap.add_argument("--wallets-per-psp", type=int, default=5_000)
    ap.add_argument("--cross-border-p", type=float, default=0.25)
    ap.add_argument("--sanctioned-p", type=float, default=0.002)
    ap.add_argument("--amt-mean", type=float, default=120.0)
    ap.add_argument("--amt-sigma", type=float, default=1.0)
    ap.add_argument("--structuring-p", type=float, default=0.002)
    ap.add_argument("--use-stark", action="store_true")

    ap.add_argument("--psi-mean-ms", type=float, default=450.0)
    ap.add_argument("--zk-prove-mean-ms", type=float, default=60.0)
    ap.add_argument("--ledger-verify-mean-ms", type=float, default=2.0)
    args = ap.parse_args()

    cfg = SimConfig(
        seed=args.seed,
        days=args.days,
        tx_per_day=args.tx_per_day,
        psps=args.psps,
        wallets_per_psp=args.wallets_per_psp,
        cross_border_p=args.cross_border_p,
        sanctioned_p=args.sanctioned_p,
        amt_mean=args.amt_mean,
        amt_sigma=args.amt_sigma,
        structuring_p=args.structuring_p,
        psi_mean_ms=args.psi_mean_ms,
        zk_prove_mean_ms=args.zk_prove_mean_ms,
        ledger_verify_mean_ms=args.ledger_verify_mean_ms,
        use_stark=args.use_stark,
    )

    sim = PETAMLSimulator(cfg)
    res = sim.run()
    summarize(res, cfg)


if __name__ == "__main__":
    main()
