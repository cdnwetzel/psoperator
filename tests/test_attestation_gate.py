"""R-203 — the gatekeeper authenticates observer envelopes, adversarially.

`attestation_signature_matches` checks only key identity + signature and says so:
"R-203 owns policy and replay checks." This is that owner — a stateful gate that
admits an :class:`AttestedSnapshot` only if it survives every attack an
injected/compromised planner can mount, and receipts the verdict either way.

Written adversary-first: each test is an attack that must fail closed —
a fabricated signature, an unknown key, an expired or future-dated envelope, a
replayed nonce, and a rolled-back (stale) observer epoch. The positive control
proves the gate still admits a genuine one, so the refusals aren't vacuous.
"""

from __future__ import annotations

import pytest

from psoperator.common.attestation import AttestationKey, AttestationKeyring, SnapshotSigner
from psoperator.common.schema import PerceptionSnapshot
from psoperator.gatekeeper.attestation_gate import AttestationGate, EnvelopeRejected

KEY_ID = "observer-2026-09"
EPOCH_A = "a" * 64
EPOCH_B = "b" * 64
NONCE_1 = "1" * 64


def _key(secret: bytes = b"s" * 32, key_id: str = KEY_ID) -> AttestationKey:
    return AttestationKey(key_id, secret, created_at=90.0)


def _snapshot(frame_hash: str = "f" * 64) -> PerceptionSnapshot:
    return PerceptionSnapshot(
        frame_id=7, captured_at=100.0, frame_hash=frame_hash, screen_size=(80, 60)
    )


def _signer(key: AttestationKey, *, epoch: str = EPOCH_A, ttl: float = 10.0,
            nonce: str | None = None) -> SnapshotSigner:
    return SnapshotSigner(
        key, ttl_s=ttl, observer_epoch=epoch,
        nonce_factory=(lambda: nonce) if nonce else None,
    )


def _gate(*, keyring=None, epoch=EPOCH_A, receipts=None):
    kr = keyring or AttestationKeyring([_key()])
    record = receipts.append if receipts is not None else None
    return AttestationGate(kr, expected_epoch=epoch, record=record)


# --- positive control -------------------------------------------------------


def test_a_genuine_envelope_is_admitted_and_receipted():
    receipts: list[dict] = []
    gate = _gate(receipts=receipts)
    env = _signer(_key()).sign(_snapshot(), issued_at=101.0)
    admitted = gate.admit(env, now=105.0)
    assert admitted.frame_hash == "f" * 64
    assert admitted.observer_epoch == EPOCH_A
    assert receipts and receipts[-1]["outcome"] == "admitted"


# --- the attacks, each must fail closed -------------------------------------


def test_a_fabricated_signature_is_rejected():
    # An attacker signs with the right key_id but the wrong secret.
    forged = _signer(_key(secret=b"x" * 32)).sign(_snapshot(), issued_at=101.0)
    gate = _gate()  # keyring holds the REAL secret for KEY_ID
    with pytest.raises(EnvelopeRejected) as exc:
        gate.admit(forged, now=105.0)
    assert exc.value.reason == "bad-signature"


def test_an_unknown_key_is_rejected():
    ghost = _signer(_key(key_id="ghost-key")).sign(_snapshot(), issued_at=101.0)
    gate = _gate()  # keyring has KEY_ID only, not "ghost-key"
    with pytest.raises(EnvelopeRejected) as exc:
        gate.admit(ghost, now=105.0)
    assert exc.value.reason == "unknown-key"


def test_an_expired_envelope_is_rejected():
    env = _signer(_key(), ttl=10.0).sign(_snapshot(), issued_at=101.0)  # expires 111
    gate = _gate()
    with pytest.raises(EnvelopeRejected) as exc:
        gate.admit(env, now=200.0)
    assert exc.value.reason == "expired"


def test_a_future_dated_envelope_is_rejected():
    env = _signer(_key()).sign(_snapshot(), issued_at=500.0)  # issued in the future
    gate = _gate()
    with pytest.raises(EnvelopeRejected) as exc:
        gate.admit(env, now=105.0)  # now < issued_at
    assert exc.value.reason == "not-yet-valid"


def test_a_replayed_nonce_is_rejected():
    env = _signer(_key(), nonce=NONCE_1).sign(_snapshot(), issued_at=101.0)
    gate = _gate()
    gate.admit(env, now=105.0)  # first time: admitted
    with pytest.raises(EnvelopeRejected) as exc:
        gate.admit(env, now=106.0)  # same nonce, still fresh: a replay
    assert exc.value.reason == "replayed-nonce"


def test_a_stale_epoch_envelope_is_rejected():
    # The observer restarted (new epoch); an attacker replays an envelope from
    # the old/other epoch. The gate is pinned to EPOCH_A and refuses EPOCH_B.
    other = _signer(_key(), epoch=EPOCH_B).sign(_snapshot(), issued_at=101.0)
    gate = _gate(epoch=EPOCH_A)
    with pytest.raises(EnvelopeRejected) as exc:
        gate.admit(other, now=105.0)
    assert exc.value.reason == "stale-epoch"


# --- properties across all rejections ---------------------------------------


def test_every_rejection_is_receipted_and_admits_nothing():
    receipts: list[dict] = []
    # one gate, a sequence of distinct attacks; each must record a rejection.
    gate = _gate(receipts=receipts)
    attacks = [
        _signer(_key(secret=b"x" * 32)).sign(_snapshot(), issued_at=101.0),   # bad sig
        _signer(_key(key_id="ghost-key")).sign(_snapshot(), issued_at=101.0),  # unknown key
        _signer(_key(), epoch=EPOCH_B).sign(_snapshot(), issued_at=101.0),     # stale epoch
    ]
    for env in attacks:
        with pytest.raises(EnvelopeRejected):
            gate.admit(env, now=105.0)
    assert len(receipts) == len(attacks)
    assert all(r["outcome"] == "rejected" and r["reason"] for r in receipts)


def test_tofu_pins_the_first_epoch_then_refuses_others():
    # With no expected_epoch, the gate trusts the first epoch it admits, then
    # treats any other as a rollback — a later trust decision, not automatic.
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=None)
    first = _signer(_key(), epoch=EPOCH_A, nonce=NONCE_1).sign(_snapshot(), issued_at=101.0)
    gate.admit(first, now=105.0)
    with pytest.raises(EnvelopeRejected) as exc:
        other = _signer(_key(), epoch=EPOCH_B).sign(_snapshot(), issued_at=101.0)
        gate.admit(other, now=105.0)
    assert exc.value.reason == "stale-epoch"


# --- frame-rollback (monotonic frame id) ------------------------------------


def _env_frame(frame_id: int, nonce: str):
    snap = PerceptionSnapshot(
        frame_id=frame_id, captured_at=100.0, frame_hash="f" * 64, screen_size=(80, 60)
    )
    signer = SnapshotSigner(_key(), ttl_s=10.0, observer_epoch=EPOCH_A, nonce_factory=lambda: nonce)
    return signer.sign(snap, issued_at=101.0)


def test_a_non_increasing_frame_is_rejected_as_a_rollback():
    # An older frame (7), freshly re-attested with a new nonce, passes signature/
    # epoch/lifetime/nonce — but arriving after frame 8 it is a rollback.
    gate = _gate()
    gate.admit(_env_frame(8, "8" * 64), now=105.0)
    with pytest.raises(EnvelopeRejected) as exc:
        gate.admit(_env_frame(7, "7" * 64), now=105.0)
    assert exc.value.reason == "stale-frame"


def test_frames_that_advance_are_admitted():
    gate = _gate()
    gate.admit(_env_frame(8, "8" * 64), now=105.0)
    gate.admit(_env_frame(9, "9" * 64), now=105.0)  # advances past 8 -> admitted, no raise


def test_max_nonces_below_one_is_refused():
    # A cap < 1 would evict every nonce on insert, silently disabling replay
    # rejection — the constructor refuses it (psoperator #4).
    import pytest as _pytest

    with _pytest.raises(ValueError, match="max_nonces"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, max_nonces=0)
