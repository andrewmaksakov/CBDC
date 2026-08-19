"""World-grid constructors for the E3/E4 DGP surface (protocol §5).

Two named axes, three levels each, plus a prevalence sweep. The default
world (b=mid, s=mid, p=0.05) is REQUIRED to be field-identical to
``dgp.default_config`` — enforced by ``test_ladder.py`` — so every prior
result remains the unmodified mid/mid point of the surface.

Axis semantics:

* Behavioral recoverability ``b`` maps onto the existing ``obfuscation``
  knob only (higher obfuscation = lower recoverability). Laundering
  volume/cycle parameters are deliberately NOT varied, so the axis is
  pure signal-recoverability, not signal-quantity.
* Identity signal ``s`` sets the nine identity-attribute parameters as a
  block. ``low`` sets every launderer parameter equal to its legitimate
  counterpart (identity attributes carry zero class signal by
  construction). ``mid`` is the current class-conditioned default,
  exposed here as an explicit experimenter choice. ``high`` is the
  surveillance_strong identity block (behavior parameters untouched).
"""

from __future__ import annotations

from dgp import DGPConfig, default_config

# obfuscation by recoverability level (mid == DGPConfig default)
_B_OBFUSCATION = {"low": 0.9, "mid": 0.6, "high": 0.3}

# identity-attribute blocks by signal level
_S_IDENTITY = {
    # zero class signal: launderer parameters == legit parameters
    "low": dict(
        watchlist_tpr=0.02,            # == watchlist_fpr
        sar_lambda_launderer=0.10,     # == sar_lambda_legit
        kyc_low_prob_launderer=0.30,   # == kyc_low_prob_legit
        juris_beta_launderer=(2.0, 5.0),
        acct_age_mu_launderer=6.3,
    ),
    # current default: class-conditioned, overlapping
    "mid": dict(),
    # surveillance_strong identity block (dgp.surveillance_strong_config),
    # WITHOUT its behavioral changes
    "high": dict(
        watchlist_tpr=0.72,
        watchlist_fpr=0.02,
        sar_lambda_launderer=1.20,
        sar_lambda_legit=0.05,
        kyc_low_prob_launderer=0.70,
        kyc_low_prob_legit=0.20,
        juris_beta_launderer=(3.5, 3.0),
        juris_beta_legit=(1.8, 5.0),
    ),
}

B_LEVELS = ("low", "mid", "high")
S_LEVELS = ("low", "mid", "high")
PREVALENCES = (0.01, 0.03, 0.05)


def world_config(b: str, s: str, prevalence: float, seed: int,
                 n_entities: int = 8000) -> DGPConfig:
    """One surface world. (b=mid, s=mid, p=0.05) == default_config."""
    if b not in _B_OBFUSCATION:
        raise ValueError(f"unknown recoverability level {b!r}")
    if s not in _S_IDENTITY:
        raise ValueError(f"unknown identity-signal level {s!r}")
    cfg = default_config(seed=seed)
    cfg.n_entities = n_entities
    cfg.base_rate = float(prevalence)
    cfg.obfuscation = _B_OBFUSCATION[b]
    for k, v in _S_IDENTITY[s].items():
        setattr(cfg, k, v)
    cfg.label = f"b={b}|s={s}|p={prevalence:g}"
    return cfg
