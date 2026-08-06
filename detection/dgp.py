"""Non-degenerate synthetic CBDC transaction generator (the T0-2 fix).

Design contract (see DESIGN_PACK_JUL2026.md §4.1):

* Wallet counts per entity are drawn from a SINGLE shared distribution for
  both classes. Laundering is a latent multi-step behavioral property
  (placement -> layering across own wallets -> integration), never a
  single separable marginal feature.
* Prevalence is realistic (1-5% illicit) and configurable.
* Obfuscation strength is a behavioral knob: it blends launderers into
  legitimate cover activity and jitters the layering timing, it does NOT
  change wallet counts.
* Identity attributes (KYC tier, account age, prior SARs, jurisdiction
  risk, watchlist membership) are informative-but-noisy, with class-
  conditional distributions that overlap. Watchlist coverage is partial
  by construction (real watchlists are).

Every draw goes through one numpy Generator seeded from ``DGPConfig.seed``.

Output schema (the standard interface real data must map onto, see
data_loaders.py):

entities:      entity_id, is_launderer, kyc_tier, account_age_days,
               prior_sar_count, jurisdiction_risk, on_watchlist
wallets:       wallet_id, entity_id
transactions:  src, dst, amount, t   (wallet ids; externals prefixed "X")
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

import numpy as np
import pandas as pd


@dataclass
class DGPConfig:
    seed: int = 20260707
    # Cheap default for tests and the standalone degeneracy gate ONLY.
    # The canonical experiment size is 8000, set by run_all.py --n-entities;
    # at 800 only ~29 launderers survive and the tiers are not separately
    # identified. Do not quote a result generated at this default.
    n_entities: int = 800
    base_rate: float = 0.05           # fraction of entities that launder
    sim_days: float = 120.0
    obfuscation: float = 0.6          # 0 = blatant layering, 1 = heavy cover
    reporting_threshold: float = 10_000.0
    n_external: int = 3000            # shared pool of external wallets

    # shared wallet-count distribution: 1 + Binomial(5, p) for BOTH classes
    wallet_count_p: float = 0.30

    # laundering behavior
    cycles_per_120d: float = 3.0      # mean laundering cycles per entity
    placement_mu: float = 8.25        # ln-scale, exp(8.25) ~ 3800
    placement_sigma: float = 0.60
    smurf_prob: float = 0.60          # placement arrives as several chunks

    # identity-attribute informativeness (surveillance_strong cranks these)
    watchlist_tpr: float = 0.40       # P(on watchlist | launderer)
    watchlist_fpr: float = 0.02       # P(on watchlist | legit)
    sar_lambda_launderer: float = 0.40
    sar_lambda_legit: float = 0.10
    kyc_low_prob_launderer: float = 0.45
    kyc_low_prob_legit: float = 0.30
    juris_beta_launderer: tuple = (2.4, 4.0)   # mean ~0.375
    juris_beta_legit: tuple = (2.0, 5.0)       # mean ~0.286
    acct_age_mu_launderer: float = 5.9         # exp(5.9) ~ 365 days
    acct_age_mu_legit: float = 6.3             # exp(6.3) ~ 545 days
    acct_age_sigma: float = 0.7

    label: str = "default"

    def to_dict(self):
        return asdict(self)


def default_config(seed: int = 20260707) -> DGPConfig:
    return DGPConfig(seed=seed)


def surveillance_strong_config(seed: int = 20260707) -> DGPConfig:
    """Falsification-demo world: identity/watchlist genuinely informative.

    Launderers hide behaviorally (obfuscation near max, few small cycles)
    while identity attributes and the watchlist carry real signal — the
    world in which full surveillance genuinely beats pseudonymous linkage.
    Every single feature still passes the degeneracy audit (each identity
    marginal is tuned to stay below the 0.95 cap), but T3/T4 should beat
    T2 beyond any sane equivalence margin. If the TOST harness cannot
    return SURVEILLANCE_SUPERIOR on this config, the harness is rigged
    and must not be used.
    """
    return DGPConfig(
        seed=seed,
        obfuscation=0.95,
        cycles_per_120d=1.5,
        placement_mu=7.9,             # exp(7.9) ~ 2700, deep in legit band
        watchlist_tpr=0.72,
        watchlist_fpr=0.02,
        sar_lambda_launderer=1.20,
        sar_lambda_legit=0.05,
        kyc_low_prob_launderer=0.70,
        kyc_low_prob_legit=0.20,
        juris_beta_launderer=(3.5, 3.0),
        juris_beta_legit=(1.8, 5.0),
        label="surveillance_strong",
    )


# ---------------------------------------------------------------------------
# legitimate activity (also used as cover activity by launderers)
# ---------------------------------------------------------------------------

_LEGIT_TYPES = ("saver", "spender", "business")
_LEGIT_TYPE_P = (0.35, 0.45, 0.20)


def _rand_ext(rng, n_external):
    return f"X{rng.integers(n_external)}"


def _legit_stream(rng, wallets, etype, cfg, rate_scale=1.0):
    """Income / spending / self-transfer stream for one entity.

    Returns list of (src, dst, amount, t). Big-ticket transfers and
    business turnover deliberately overlap the launderers' placement and
    pass-through bands so no marginal feature is class-disjoint.
    """
    txs = []
    days = cfg.sim_days
    nw = len(wallets)

    def own(t=None):
        return wallets[rng.integers(nw)]

    if etype == "business":
        # frequent revenue in, frequent expenses out: a natural fast-
        # pass-through confuser for the layering signal
        n_rev = rng.poisson(0.8 * days * rate_scale)
        for t in np.sort(rng.uniform(0, days, n_rev)):
            txs.append((_rand_ext(rng, cfg.n_external), own(),
                        rng.lognormal(np.log(900), 0.9), t))
        n_exp = rng.poisson(0.5 * days * rate_scale)
        for t in np.sort(rng.uniform(0, days, n_exp)):
            txs.append((own(), _rand_ext(rng, cfg.n_external),
                        rng.lognormal(np.log(700), 1.0), t))
        # monthly payroll-sized outflows, some in the near-threshold band
        t = rng.uniform(0, 30)
        while t < days:
            txs.append((own(), _rand_ext(rng, cfg.n_external),
                        rng.lognormal(np.log(5000), 0.6), t))
            t += 30 + rng.normal(0, 3)
    else:
        # salary-like income
        income_times = []
        t = rng.uniform(0, 30)
        while t < days:
            txs.append((_rand_ext(rng, cfg.n_external), own(),
                        rng.lognormal(np.log(2800), 0.5), t))
            income_times.append(t)
            t += 30 + rng.normal(0, 3)
        spend_rate = {"saver": 0.25, "spender": 0.60}[etype] * rate_scale
        n_spend = rng.poisson(spend_rate * days)
        for _ in range(n_spend):
            # payday effect: half of spending clusters shortly after an
            # income event (gives legit wallets fast pass-through and
            # bursty gaps, overlapping the layering timing signal)
            if income_times and rng.random() < 0.6:
                t = income_times[rng.integers(len(income_times))] \
                    + rng.exponential(1.2)
            else:
                t = rng.uniform(0, days)
            if t >= days:
                continue
            txs.append((own(), _rand_ext(rng, cfg.n_external),
                        rng.lognormal(np.log(60), 1.1), t))
            # burst clusters: some spending comes in same-day runs
            if rng.random() < 0.25:
                for _ in range(rng.integers(1, 3)):
                    tt = t + rng.uniform(0, 0.4)
                    if tt < days:
                        txs.append((own(), _rand_ext(rng, cfg.n_external),
                                    rng.lognormal(np.log(60), 1.1), tt))

    # occasional big-ticket transfers (rent, car, deposit) — overlaps the
    # placement / structuring amount band for both classes
    n_big = rng.poisson(0.012 * days)
    for t in rng.uniform(0, days, n_big):
        txs.append((own(), _rand_ext(rng, cfg.n_external),
                    rng.lognormal(np.log(4500), 0.8), t))

    # legit self-transfers between own wallets (so "has internal
    # transfers" is not a laundering tell once linkage is known)
    if nw > 1:
        n_self = rng.poisson(0.06 * days)
        for t in rng.uniform(0, days, n_self):
            a, b = rng.choice(nw, size=2, replace=False)
            txs.append((wallets[a], wallets[b],
                        rng.lognormal(np.log(500), 1.0), t))
            # some self-transfers precede spending shortly after, giving
            # legit entities fast internal->external chains too
            if rng.random() < 0.5:
                txs.append((wallets[b], _rand_ext(rng, cfg.n_external),
                            rng.lognormal(np.log(400), 0.9),
                            t + rng.exponential(1.0)))
    return txs


# ---------------------------------------------------------------------------
# laundering cycles: placement -> layering -> integration
# ---------------------------------------------------------------------------

def _laundering_cycles(rng, wallets, cfg):
    """Latent laundering behavior for one entity.

    A cycle: dirty inflow from an ordinary external wallet (no dedicated
    'dirty source' set — source-based detection is deliberately impossible),
    split into parts, hopped through the entity's own wallets with short
    lags and small retention, then paid out to external wallets, structured
    below the reporting threshold when a part is large.
    """
    txs = []
    obf = cfg.obfuscation
    nw = len(wallets)
    # not every wallet takes part in laundering: keep some as pure cover,
    # so the entity's least-suspicious wallet looks fully legitimate
    n_active = max(1, int(np.ceil(nw * rng.uniform(0.5, 1.0))))
    wallets = list(rng.choice(wallets, size=n_active, replace=False))
    nw = n_active
    n_cycles = 1 + rng.poisson(cfg.cycles_per_120d * cfg.sim_days / 120.0)
    hop_lag_mean = 1.5 + 2.0 * obf          # days; obfuscation slows hops
    for _ in range(n_cycles):
        t0 = rng.uniform(2, cfg.sim_days - 8)
        amount = rng.lognormal(cfg.placement_mu, cfg.placement_sigma)
        w_in = wallets[rng.integers(nw)]
        # smurfed placement: dirty funds often arrive as several
        # sub-threshold chunks, so max-inflow is not a separator
        if rng.random() < cfg.smurf_prob and amount > 4000:
            left, tc = amount, t0
            while left > 0:
                c = min(left, rng.uniform(1500, 6000))
                txs.append((_rand_ext(rng, cfg.n_external), w_in, c, tc))
                tc += rng.exponential(0.7)
                left -= c
        else:
            txs.append((_rand_ext(rng, cfg.n_external), w_in, amount, t0))
        k = rng.integers(2, 6)               # split into 2-5 parts
        parts = amount * rng.dirichlet(np.ones(k) * 4.0)
        for part in parts:
            w_cur, t_cur, remaining = w_in, t0, part
            n_hops = rng.integers(1, 4) if nw > 1 else 0
            for _ in range(n_hops):
                w_next = wallets[rng.integers(nw)]
                if w_next == w_cur:
                    continue
                t_cur += rng.exponential(hop_lag_mean)
                remaining *= rng.uniform(0.97, 1.0)   # hop retention/fees
                txs.append((w_cur, w_next, remaining, t_cur))
                w_cur = w_next
            # integration: out to ordinary externals; structure large parts
            t_cur += rng.exponential(hop_lag_mean)
            thr = cfg.reporting_threshold
            chunks = [remaining]
            if remaining >= 0.95 * thr and rng.random() < (0.7 - 0.4 * obf):
                chunks = []
                left = remaining
                while left > 0.95 * thr:
                    c = rng.uniform(0.72, 0.97) * thr
                    chunks.append(c)
                    left -= c
                if left > 0:
                    chunks.append(left)
            for c in chunks:
                txs.append((w_cur, _rand_ext(rng, cfg.n_external), c, t_cur))
                t_cur += rng.exponential(0.5 + 1.0 * obf)
    return txs


# ---------------------------------------------------------------------------
# identity attributes
# ---------------------------------------------------------------------------

def _identity_attrs(rng, is_launderer, cfg):
    n = len(is_launderer)
    lau = is_launderer.astype(bool)

    kyc_low_p = np.where(lau, cfg.kyc_low_prob_launderer, cfg.kyc_low_prob_legit)
    u = rng.random(n)
    kyc_tier = np.where(u < kyc_low_p, 0, np.where(u < kyc_low_p + 0.4, 1, 2))

    age_mu = np.where(lau, cfg.acct_age_mu_launderer, cfg.acct_age_mu_legit)
    account_age = rng.lognormal(age_mu, cfg.acct_age_sigma)

    sar_lam = np.where(lau, cfg.sar_lambda_launderer, cfg.sar_lambda_legit)
    prior_sar = rng.poisson(sar_lam)

    juris = np.where(
        lau,
        rng.beta(*cfg.juris_beta_launderer, size=n),
        rng.beta(*cfg.juris_beta_legit, size=n),
    )

    wl_p = np.where(lau, cfg.watchlist_tpr, cfg.watchlist_fpr)
    on_watchlist = (rng.random(n) < wl_p).astype(int)

    return kyc_tier, account_age, prior_sar, juris, on_watchlist


# ---------------------------------------------------------------------------
# generator
# ---------------------------------------------------------------------------

def generate(cfg: DGPConfig) -> dict:
    """Generate one synthetic world. Returns dict of DataFrames
    (entities, wallets, transactions) conforming to the standard schema."""
    rng = np.random.default_rng(cfg.seed)
    n = cfg.n_entities

    is_launderer = (rng.random(n) < cfg.base_rate).astype(int)

    # THE critical line: one shared wallet-count distribution, both classes
    wallet_counts = 1 + rng.binomial(5, cfg.wallet_count_p, size=n)

    kyc, age, sar, juris, wl = _identity_attrs(rng, is_launderer, cfg)
    entities = pd.DataFrame({
        "entity_id": [f"E{i}" for i in range(n)],
        "is_launderer": is_launderer,
        "kyc_tier": kyc,
        "account_age_days": age,
        "prior_sar_count": sar,
        "jurisdiction_risk": juris,
        "on_watchlist": wl,
    })

    wallet_rows, all_txs = [], []
    widx = 0
    for i in range(n):
        wallets = [f"W{widx + j}" for j in range(wallet_counts[i])]
        widx += wallet_counts[i]
        wallet_rows += [(w, f"E{i}") for w in wallets]

        etype = rng.choice(_LEGIT_TYPES, p=_LEGIT_TYPE_P)
        if is_launderer[i]:
            # cover activity scales with obfuscation; laundering rides on top
            cover_scale = 0.7 + 0.3 * cfg.obfuscation
            all_txs += _legit_stream(rng, wallets, etype, cfg, cover_scale)
            all_txs += _laundering_cycles(rng, wallets, cfg)
        else:
            all_txs += _legit_stream(rng, wallets, etype, cfg)

    wallets_df = pd.DataFrame(wallet_rows, columns=["wallet_id", "entity_id"])
    tx = pd.DataFrame(all_txs, columns=["src", "dst", "amount", "t"])
    tx = tx[(tx.t >= 0) & (tx.t <= cfg.sim_days) & (tx.amount > 0)]
    tx = tx.sort_values("t", kind="stable").reset_index(drop=True)

    return {"entities": entities, "wallets": wallets_df, "transactions": tx,
            "config": cfg}
