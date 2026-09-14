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

import json

import pytest

from psoperator.common.attestation import AttestationKey, AttestationKeyring, SnapshotSigner
from psoperator.common.schema import PerceptionSnapshot
from psoperator.gatekeeper.attestation_gate import (
    AttestationGate,
    EnvelopeRejected,
    GateStateError,
)

KEY_ID = "observer-2026-09"
EPOCH_A = "a" * 64
EPOCH_B = "b" * 64
NONCE_1 = "1" * 64


def _key(secret: bytes = b"s" * 32, key_id: str = KEY_ID) -> AttestationKey:
    return AttestationKey(key_id, secret, created_at=90.0)


def _snapshot(frame_hash: str = "f" * 64, frame_id: int = 7) -> PerceptionSnapshot:
    return PerceptionSnapshot(
        frame_id=frame_id, captured_at=100.0, frame_hash=frame_hash, screen_size=(80, 60)
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


def test_a_non_integer_nonce_cap_is_refused():
    # A float (0.5, 1.5) or a bool (True) is a config bug: it never trips the
    # eviction cleanly and would silently weaken replay rejection. The cap must be
    # a real int >= 1 (CodeRabbit, psoperator #10).
    import pytest as _pytest

    for bad in (0.5, 1.5, True):
        with _pytest.raises(ValueError, match="integer"):
            AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, max_nonces=bad)


# --- D1: the frame watermark must survive a restart -------------------------
#
# `observer_epoch` is pinned out of band precisely so "a service restart cannot
# be tricked into trust-on-first-use pinning an attacker's epoch (CWE-384)".
# The frame watermark had the identical weakness and never got the same fix:
# it lived only in memory, so every restart disarmed the stale-frame check.


def _captured_envelopes(count: int = 4, *, ttl: float = 50.0):
    """Envelopes an attacker could have observed on the wire, still inside TTL."""
    return [
        _signer(_key(), ttl=ttl, nonce=str(i) * 64).sign(
            _snapshot(frame_id=i), issued_at=101.0
        )
        for i in range(1, count + 1)
    ]


def test_a_restart_with_no_persisted_state_readmits_a_captured_envelope():
    """The bug, stated as the attack it enables.

    With the watermark in memory only, restarting the gatekeeper empties both the
    nonce set and the frame watermark — so any envelope captured within the last
    TTL replays cleanly. This is not narrowly about nonce-set eviction: nothing
    needs to have been evicted, because a restart drops everything.
    """
    envelopes = _captured_envelopes()
    live = _gate()
    for envelope in envelopes:
        live.admit(envelope, now=105.0)

    restarted = _gate()  # no state_path — today's default
    admitted = restarted.admit(envelopes[0], now=105.0)
    assert admitted.nonce == "1" * 64, (
        "a stateless restart is expected to re-admit a replay; if this now refuses, "
        "the durability fix has become the default and this regression test should say so"
    )


def test_the_watermark_survives_a_restart_and_the_replay_is_refused(tmp_path):
    state = tmp_path / "gate_state.json"
    envelopes = _captured_envelopes()
    live = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
    )
    for envelope in envelopes:
        live.admit(envelope, now=105.0)

    restarted = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
    )
    with pytest.raises(EnvelopeRejected) as rejection:
        restarted.admit(envelopes[0], now=105.0)
    assert rejection.value.reason == "stale-frame"


def test_a_restart_refuses_even_the_most_recent_envelope(tmp_path):
    """The watermark compares with `<=`, so the newest admitted frame is refused
    too — otherwise the single most useful envelope to capture stays replayable."""
    state = tmp_path / "gate_state.json"
    envelopes = _captured_envelopes()
    live = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
    )
    for envelope in envelopes:
        live.admit(envelope, now=105.0)

    restarted = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
    )
    with pytest.raises(EnvelopeRejected) as rejection:
        restarted.admit(envelopes[-1], now=105.0)
    assert rejection.value.reason == "stale-frame"


@pytest.mark.parametrize(
    "content",
    ["{not json", '{"last_frame_id": -1}', '{"last_frame_id": true}',
     '{"last_frame_id": "7"}', '{"last_frame_id": 7.5}', "[1, 2]", '{}'],
    ids=["unparseable", "negative", "bool", "string", "float", "not-an-object", "absent"],
)
def test_state_that_cannot_be_trusted_refuses_to_start(tmp_path, content):
    """Fail closed. Starting with no watermark is the exact state the file exists
    to prevent, so a state file that exists but cannot be read is never treated
    as 'no state' — that would turn a corrupted file into a silent downgrade."""
    state = tmp_path / "gate_state.json"
    state.write_text(content, encoding="utf-8")
    with pytest.raises(GateStateError):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


def test_a_missing_state_file_is_a_genuine_first_start(tmp_path):
    gate = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A,
        state_path=tmp_path / "absent.json",
    )
    assert gate.admit(_captured_envelopes(1)[0], now=105.0).nonce == "1" * 64


def test_state_is_written_owner_only(tmp_path):
    """Same standard as the IPC secret: created 0600, not chmod'd afterwards."""
    state = tmp_path / "nested" / "gate_state.json"
    gate = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
    )
    gate.admit(_captured_envelopes(1)[0], now=105.0)
    assert json.loads(state.read_text(encoding="utf-8")) == {"last_frame_id": 1}
    assert state.stat().st_mode & 0o777 == 0o600
    assert not list(state.parent.glob("*.tmp")), "the atomic-replace temp file leaked"


def test_a_gate_that_cannot_persist_refuses_to_admit(tmp_path):
    """If the durable record cannot be updated, admitting anyway would quietly
    restore the restart weakness with nothing reporting it."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    gate = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A,
        state_path=blocker / "gate_state.json",
    )
    with pytest.raises(GateStateError):
        gate.admit(_captured_envelopes(1)[0], now=105.0)
    assert gate._last_frame_id is None, "the watermark advanced despite the write failing"


# --- D2: evict nonces by expiry, not by how many admissions happened --------


def test_expired_nonces_are_evicted_by_ttl_not_by_admission_count():
    gate = _gate()
    for envelope in _captured_envelopes(4):
        gate.admit(envelope, now=105.0)
    assert len(gate._seen) == 4, "nothing has expired yet, so nothing may be forgotten"

    later = _signer(_key(), ttl=50.0, nonce="9" * 64).sign(
        _snapshot(frame_id=9), issued_at=150.0
    )
    gate.admit(later, now=152.0)
    assert len(gate._seen) == 1, "the first four expired at t=151 and must be gone"


def test_forgetting_an_expired_nonce_costs_no_replay_protection():
    """Why expiry-driven eviction is free: `_verify` rejects an expired envelope
    *before* it consults the nonce set, so the forgotten nonce was doing no work."""
    gate = _gate()
    envelope = _captured_envelopes(1)[0]
    gate.admit(envelope, now=105.0)
    with pytest.raises(EnvelopeRejected) as rejection:
        gate.admit(envelope, now=152.0)
    assert rejection.value.reason == "expired"


def test_the_ceiling_receipts_when_it_drops_a_still_valid_nonce():
    """The ceiling cannot make the same promise expiry can, so when it evicts a
    nonce that is still inside its lifetime the gate says so rather than quietly
    weakening itself — declared, not silent."""
    receipts: list[dict] = []
    gate = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A,
        record=receipts.append, max_nonces=3,
    )
    for envelope in _captured_envelopes(4):
        gate.admit(envelope, now=105.0)

    evictions = [r for r in receipts if r["outcome"] == "nonce-evicted-unexpired"]
    assert len(evictions) == 1
    assert evictions[0]["nonce"] == "1" * 64
    assert evictions[0]["reason"] == "max-nonces"


def test_no_eviction_receipt_when_the_ceiling_is_never_reached():
    """A receipt that fires in normal operation would train an operator to ignore it."""
    receipts: list[dict] = []
    gate = _gate(receipts=receipts)
    for envelope in _captured_envelopes(4):
        gate.admit(envelope, now=105.0)
    assert not [r for r in receipts if r["outcome"] == "nonce-evicted-unexpired"]
    assert len(receipts) == 4, "still exactly one admission receipt per call"
