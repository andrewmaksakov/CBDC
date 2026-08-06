"""The gate must actually refuse. Each test is a way of getting a
confirmatory run started that the freeze is supposed to block."""

import json
import os
import tempfile

import protocol_lock as pl

SIG = [{"name": "Murad Farzulla", "role": "lead author", "date": "2026-08-06"}]


def _lock(**over):
    d = dict(pl.PROPOSED)
    d.update({"R": 52, "D4_delta_star": 10.0, "signatures": SIG})
    d.update(over)
    d["lock_sha256"] = pl.compute_hash(d)
    return d


def _expect(lock, needle, allow_unsigned=False):
    try:
        pl.validate(lock, allow_unsigned=allow_unsigned)
    except pl.LockError as e:
        assert needle in str(e).lower(), f"wrong reason: {e}"
        return
    raise AssertionError(f"should have refused ({needle})")


def test_valid_lock_passes():
    pl.validate(_lock())


def test_missing_file_refuses():
    try:
        pl.load(os.path.join(tempfile.gettempdir(), "definitely-absent.json"))
    except pl.LockError as e:
        assert "no protocol lock" in str(e)
        return
    raise AssertionError("missing lock should refuse")


def test_unsigned_refuses():
    _expect(_lock(signatures=[]), "unsigned")


def test_wrong_role_refuses():
    _expect(_lock(signatures=[{"name": "X", "role": "reviewer",
                               "date": "2026-08-06"}]), "unsigned")


def test_tampered_lock_refuses():
    """Edit a frozen value after signing and the hash stops matching."""
    lock = _lock()
    lock["D3_k_star"] = 50          # the value the pilot showed is saturated
    _expect(lock, "hash mismatch")


def test_missing_R_refuses():
    lock = dict(pl.PROPOSED)
    lock.update({"D4_delta_star": 10.0, "signatures": SIG, "R": None})
    lock["lock_sha256"] = pl.compute_hash(lock)
    _expect(lock, "no r")


def test_burned_seed_reuse_refuses():
    """Confirmatory seeds may never touch the burned pilot seeds."""
    _expect(_lock(conf_seed_base=900_001), "burned")


def test_oversized_seed_base_refuses():
    """The bug that killed the first confirmatory attempt: a seed base above
    sklearn's random_state ceiling. The gate must catch it, not the 20th
    replicate."""
    _expect(_lock(conf_seed_base=20_260_805_001), "ceiling")


def test_saturated_budget_refuses():
    """The whole point: k*=50 cannot be frozen without an amendment."""
    _expect(_lock(D3_k_star=50), "saturated")


def test_template_is_written_unsigned():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "protocol_lock.json")
        pl.write_template(p)
        lock = json.load(open(p))
        assert lock["signatures"] == []
        assert lock["D4_delta_star"] is None
        assert lock["R"] is None
        _expect(lock, "unsigned")       # a fresh template authorises nothing


def test_hash_is_order_independent():
    a = _lock()
    b = {k: a[k] for k in reversed(list(a))}
    assert pl.compute_hash(a) == pl.compute_hash(b)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS: {fn.__name__}")
    print(f"\nall {len(fns)} lock tests passed")
