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
import os
import subprocess

import pytest

from psoperator.common import winacl
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

# Root ignores directory permission bits, so a write the test denies succeeds.
_needs_non_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses directory permission bits",
)
_posix_modes = pytest.mark.skipif(
    os.name == "nt", reason="POSIX mode bits; the _windows counterpart checks the DACL"
)
_windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows DACLs")


def _icacls(path, *args: str) -> None:
    subprocess.run(["icacls", str(path), *args], check=True, capture_output=True)


def _key(secret: bytes = b"s" * 32, key_id: str = KEY_ID) -> AttestationKey:
    return AttestationKey(key_id, secret, created_at=90.0)


def _snapshot(frame_hash: str = "f" * 64, frame_id: int = 7) -> PerceptionSnapshot:
    return PerceptionSnapshot(
        frame_id=frame_id, captured_at=100.0, frame_hash=frame_hash, screen_size=(80, 60)
    )


def _signer(
    key: AttestationKey, *, epoch: str = EPOCH_A, ttl: float = 10.0, nonce: str | None = None
) -> SnapshotSigner:
    return SnapshotSigner(
        key,
        ttl_s=ttl,
        observer_epoch=epoch,
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
        _signer(_key(secret=b"x" * 32)).sign(_snapshot(), issued_at=101.0),  # bad sig
        _signer(_key(key_id="ghost-key")).sign(_snapshot(), issued_at=101.0),  # unknown key
        _signer(_key(), epoch=EPOCH_B).sign(_snapshot(), issued_at=101.0),  # stale epoch
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
        _signer(_key(), ttl=ttl, nonce=str(i) * 64).sign(_snapshot(frame_id=i), issued_at=101.0)
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


def test_the_watermark_survives_a_restart_and_the_replay_is_refused(private):
    state = private.home / "gate_state.json"
    envelopes = _captured_envelopes()
    live = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    for envelope in envelopes:
        live.admit(envelope, now=105.0)

    restarted = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
    )
    with pytest.raises(EnvelopeRejected) as rejection:
        restarted.admit(envelopes[0], now=105.0)
    assert rejection.value.reason == "stale-frame"


def test_a_restart_refuses_even_the_most_recent_envelope(private):
    """The watermark compares with `<=`, so the newest admitted frame is refused
    too — otherwise the single most useful envelope to capture stays replayable."""
    state = private.home / "gate_state.json"
    envelopes = _captured_envelopes()
    live = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
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
    [
        "{not json",
        '{"last_frame_id": -1}',
        '{"last_frame_id": true}',
        '{"last_frame_id": "7"}',
        '{"last_frame_id": 7.5}',
        "[1, 2]",
        "{}",
    ],
    ids=["unparseable", "negative", "bool", "string", "float", "not-an-object", "absent"],
)
def test_state_that_cannot_be_trusted_refuses_to_start(private, content):
    """Fail closed. Starting with no watermark is the exact state the file exists
    to prevent, so a state file that exists but cannot be read is never treated
    as 'no state' — that would turn a corrupted file into a silent downgrade."""
    state = private.write(private.home / "gate_state.json", content)
    with pytest.raises(GateStateError, match="unreadable|last_frame_id|not a JSON object"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


def test_a_missing_state_file_is_a_genuine_first_start(private):
    gate = AttestationGate(
        AttestationKeyring([_key()]),
        expected_epoch=EPOCH_A,
        state_path=private.home / "absent.json",
    )
    assert gate.admit(_captured_envelopes(1)[0], now=105.0).nonce == "1" * 64


def test_state_is_written_owner_only(private):
    """Same standard as the IPC secret: created owner-only (0600, or an
    owner-only DACL on Windows), not tightened afterwards."""
    state = private.home / "nested" / "gate_state.json"
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    gate.admit(_captured_envelopes(1)[0], now=105.0)
    assert json.loads(state.read_text(encoding="utf-8")) == {
        "last_frame_id": 1,
        "last_issued_at": 101.0,
    }
    assert private.is_owner_only(state)
    assert private.is_owner_only(state.parent)
    assert not list(state.parent.glob("*.tmp")), "the atomic-replace temp file leaked"


@_needs_non_root
@_posix_modes
def test_a_gate_that_cannot_persist_refuses_to_admit(tmp_path):
    """If the durable record cannot be updated, admitting anyway would quietly
    restore the restart weakness with nothing reporting it."""
    home = tmp_path / "state"
    home.mkdir(mode=0o700)  # the gate refuses a group-writable state dir
    gate = AttestationGate(
        AttestationKeyring([_key()]),
        expected_epoch=EPOCH_A,
        state_path=home / "gate_state.json",
    )
    home.chmod(0o500)  # readable, not writable: the write must fail
    try:
        with pytest.raises(GateStateError):
            gate.admit(_captured_envelopes(1)[0], now=105.0)
    finally:
        home.chmod(0o700)
    assert gate._last_frame_id is None, "the watermark advanced despite the write failing"


@_windows_only
def test_a_gate_that_cannot_persist_refuses_to_admit_windows(private):
    """The Windows counterpart: a deny entry stops this account adding files.
    Deny entries only narrow access, so the directory is still owner-only and
    the failure is the write itself. (icacls also strips the right from the
    allow entry, so the cleanup grants full control back.)"""
    user = winacl.current_user_sid()
    gate = AttestationGate(
        AttestationKeyring([_key()]),
        expected_epoch=EPOCH_A,
        state_path=private.home / "gate_state.json",
    )
    _icacls(private.home, "/deny", f"*{user}:(WD)")
    try:
        with pytest.raises(GateStateError, match="cannot persist"):
            gate.admit(_captured_envelopes(1)[0], now=105.0)
    finally:
        _icacls(private.home, "/remove:d", f"*{user}")
        _icacls(private.home, "/grant:r", f"*{user}:(F)")
    assert gate._last_frame_id is None, "the watermark advanced despite the write failing"
    assert gate.admit(_captured_envelopes(1)[0], now=105.0).nonce == "1" * 64


def test_a_failed_write_burns_no_nonce_and_pins_no_epoch(private, monkeypatch):
    """The durable write runs before any volatile state changes. If it ran after,
    a failed write would leave the nonce burned for an envelope that was never
    admitted — and the observer could not retry, because its own nonce would come
    back as `replayed-nonce`. The failure is injected rather than made with
    directory permissions, so this also runs as root."""
    gate = AttestationGate(  # trust-on-first-use, so a failed admit could pin an epoch
        AttestationKeyring([_key()]),
        expected_epoch=None,
        state_path=private.home / "gate_state.json",
    )
    envelope = _captured_envelopes(1)[0]
    with monkeypatch.context() as patch:

        def _replace_fails(*args):
            raise OSError("injected write failure")

        if os.name == "nt":
            patch.setattr(winacl.OwnerOnlyDir, "replace", _replace_fails)
        else:
            patch.setattr(os, "replace", _replace_fails)
        with pytest.raises(GateStateError):
            gate.admit(envelope, now=105.0)
    assert gate._seen == {}, "a nonce was burned for an envelope that was not admitted"
    assert gate.pinned_epoch is None, "trust-on-first-use pinned an epoch on a failed admit"
    assert not list(private.home.glob("*.tmp")), "the failed write left its temp file"
    # and the retry now succeeds, which is the point
    assert gate.admit(envelope, now=105.0).nonce == "1" * 64


def test_a_directory_sync_failure_is_a_persistence_failure(private, monkeypatch):
    """`fsync(fd)` commits the file's bytes; the directory entry created by
    `os.replace` is a separate durability question. If that sync fails the write
    has not actually survived a crash, so it must fail the admission rather than
    report success — otherwise a reboot can return the gate to the OLD watermark
    and re-admit precisely the frames it just accepted."""
    state = private.home / "gate_state.json"
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)

    def _no_durable_dir(*args):
        raise OSError("directory sync unavailable")

    if os.name == "nt":
        monkeypatch.setattr(winacl.OwnerOnlyDir, "sync", _no_durable_dir)
    else:
        monkeypatch.setattr(AttestationGate, "_fsync_dir", staticmethod(_no_durable_dir))
    with pytest.raises(GateStateError):
        gate.admit(_captured_envelopes(1)[0], now=105.0)
    assert gate._last_frame_id is None, "the watermark advanced on an undurable write"
    assert gate._seen == {}, "a nonce was burned on an undurable write"


@_windows_only
def test_the_directory_that_received_the_rename_is_the_one_flushed(private, monkeypatch):
    """One held handle does the create, the rename and the flush. Re-opening the
    directory by path to flush it would prove nothing about the directory the
    rename went into."""
    events = []
    real_replace, real_sync = winacl.OwnerOnlyDir.replace, winacl.OwnerOnlyDir.sync
    real_init = winacl.OwnerOnlyDir.__init__

    def _replace(self, fd, name):
        events.append(("replace", id(self), self._handle))
        return real_replace(self, fd, name)

    def _sync(self):
        events.append(("sync", id(self), self._handle))
        return real_sync(self)

    def _init(self, *args, **kwargs):
        events.append(("open-by-path",))
        return real_init(self, *args, **kwargs)

    gate = AttestationGate(
        AttestationKeyring([_key()]),
        expected_epoch=EPOCH_A,
        state_path=private.home / "gate_state.json",
    )
    monkeypatch.setattr(winacl.OwnerOnlyDir, "replace", _replace)
    monkeypatch.setattr(winacl.OwnerOnlyDir, "sync", _sync)
    monkeypatch.setattr(winacl.OwnerOnlyDir, "__init__", _init)
    gate.admit(_captured_envelopes(1)[0], now=105.0)
    assert [e[0] for e in events] == ["open-by-path", "replace", "sync"]
    assert events[1][1:] == events[2][1:] and events[2][2] is not None


@pytest.mark.parametrize("chunk", [1, 3], ids=["one-byte", "three-bytes"])
def test_a_short_write_is_completed_not_persisted_short(private, monkeypatch, chunk):
    """`os.write` may write less than asked. The gate loops until the whole
    watermark is written, so a partial write never becomes the durable state."""
    state = private.home / "gate_state.json"
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    real_write = os.write
    with monkeypatch.context() as patch:
        patch.setattr(os, "write", lambda fd, data: real_write(fd, bytes(data[:chunk])))
        gate.admit(_captured_envelopes(1)[0], now=105.0)
    assert json.loads(state.read_text(encoding="utf-8")) == {
        "last_frame_id": 1,
        "last_issued_at": 101.0,
    }


def test_a_write_that_makes_no_progress_fails_closed(private, monkeypatch):
    """No progress is a failure: nothing is renamed into place, no temp file is
    left, the watermark does not advance and no nonce is burned."""
    state = private.write(
        private.home / "gate_state.json", '{"last_frame_id": 1, "last_issued_at": 101.0}'
    )
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    envelope = _lifetime_env(2, "2" * 64, 101.0)
    with monkeypatch.context() as patch:
        patch.setattr(os, "write", lambda fd, data: 0)
        with pytest.raises(GateStateError, match="short write"):
            gate.admit(envelope, now=105.0)
    assert gate._last_frame_id == 1 and gate._seen == {}
    assert json.loads(state.read_text(encoding="utf-8"))["last_frame_id"] == 1
    assert sorted(p.name for p in private.home.iterdir()) == ["gate_state.json"]
    assert gate.admit(envelope, now=105.0).nonce == "2" * 64


def test_a_symlinked_state_file_is_refused(private):
    """`read_text` follows symlinks. A watermark another account can redirect is a
    watermark it can lower, which re-opens the window this file exists to close."""
    real = private.write(private.home / "elsewhere.json", '{"last_frame_id": 1}')
    link = private.home / "gate_state.json"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("creating symlinks needs Developer Mode or the privilege")
    with pytest.raises(GateStateError):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=link)


def test_a_hard_link_to_a_file_others_can_rewrite_is_refused(tmp_path, private):
    """A hard link is the same file under a second name, with the same owner and
    permissions, so it is judged by the file it names, not by where it sits."""
    loose = tmp_path / "loose.json"
    loose.write_text('{"last_frame_id": 1}', encoding="utf-8")
    if os.name != "nt":
        loose.chmod(0o666)
    os.link(loose, private.home / "gate_state.json")
    with pytest.raises(GateStateError):
        AttestationGate(
            AttestationKeyring([_key()]),
            expected_epoch=EPOCH_A,
            state_path=private.home / "gate_state.json",
        )


def test_a_write_replaces_the_file_rather_than_writing_through_a_hard_link(tmp_path, private):
    """The watermark is replaced, never rewritten in place, so a second name for
    the old file (made before, by this account) keeps the old bytes and never
    becomes a window onto, or a lever on, the live watermark."""
    state = private.write(
        private.home / "gate_state.json", '{"last_frame_id": 1, "last_issued_at": 101.0}'
    )
    twin = tmp_path / "twin.json"
    os.link(state, twin)
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    gate.admit(_lifetime_env(2, "2" * 64, 101.0), now=105.0)
    assert json.loads(state.read_text(encoding="utf-8"))["last_frame_id"] == 2
    assert json.loads(twin.read_text(encoding="utf-8"))["last_frame_id"] == 1


@_windows_only
def test_a_retained_handle_on_the_watermark_fails_the_write_closed(private):
    """Windows refuses to rename over an open file. A handle kept on the old
    watermark therefore fails the admission: nothing advances, no nonce is
    burned, and the same envelope is admitted once the handle is gone."""
    state = private.write(
        private.home / "gate_state.json", '{"last_frame_id": 1, "last_issued_at": 101.0}'
    )
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    envelope = _lifetime_env(2, "2" * 64, 101.0)
    retained = winacl.open_owner_only_for_read(state)
    try:
        with pytest.raises(GateStateError, match="cannot persist"):
            gate.admit(envelope, now=105.0)
        assert gate._last_frame_id == 1 and gate._seen == {}
        assert json.loads(os.read(retained, 1024))["last_frame_id"] == 1
    finally:
        os.close(retained)
    assert not list(private.home.glob("*.tmp")), "the failed write left its temp file"
    assert gate.admit(envelope, now=105.0).nonce == "2" * 64


@_posix_modes
@pytest.mark.parametrize(
    "mode", [0o644, 0o660, 0o666], ids=["world-read", "group-write", "world-write"]
)
def test_a_state_file_others_can_read_or_write_is_refused(tmp_path, mode):
    """Same R-205 posture as the attestation key and the IPC secret."""
    state = tmp_path / "gate_state.json"
    state.write_text('{"last_frame_id": 1}', encoding="utf-8")
    state.chmod(mode)
    with pytest.raises(GateStateError):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


@_windows_only
@pytest.mark.parametrize("grant", ["(R)", "(M)"], ids=["everyone-reads", "everyone-modifies"])
def test_a_state_file_others_can_read_or_write_is_refused_windows(private, grant):
    state = private.write(private.home / "gate_state.json", '{"last_frame_id": 1}')
    AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    _icacls(state, "/grant", f"*S-1-1-0:{grant}")
    with pytest.raises(GateStateError, match="gate state is unsafe.*S-1-1-0"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


@_windows_only
def test_a_normally_created_state_file_is_refused(private):
    """A file made without an explicit DACL inherits one, so it is not owner-only."""
    state = private.home / "gate_state.json"
    state.write_text('{"last_frame_id": 1}', encoding="utf-8")
    with pytest.raises(GateStateError, match="gate state is unsafe"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


def test_a_non_regular_state_path_is_refused(private):
    directory = private.dir(private.home / "gate_state.json")
    with pytest.raises(GateStateError, match="not a regular file|gate state is unsafe"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=directory)


def test_a_stale_temp_file_does_not_block_the_write(private):
    """The temp name used to be `{name}.{pid}.tmp` — deterministic, so a file left
    by a crashed process could be reused, and `O_TRUNC` would have kept whatever
    mode it already had. Random name + O_EXCL means a leftover is simply ignored."""
    state = private.home / "gate_state.json"
    stale = private.home / f"{state.name}.{os.getpid()}.tmp"
    stale.write_text("leftover", encoding="utf-8")
    if os.name != "nt":
        stale.chmod(0o666)
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    gate.admit(_captured_envelopes(1)[0], now=105.0)
    assert json.loads(state.read_text(encoding="utf-8")) == {
        "last_frame_id": 1,
        "last_issued_at": 101.0,
    }
    assert private.is_owner_only(state)


def _lifetime_env(frame_id: int, nonce: str, issued_at: float):
    """An envelope from an observer lifetime whose clock reads ``issued_at``."""
    return _signer(_key(), ttl=50.0, nonce=nonce).sign(
        _snapshot(frame_id=frame_id), issued_at=issued_at
    )


def test_a_restarted_observer_is_not_locked_out_by_the_watermark(private):
    """Frame ids restart at 1 with each observer lifetime, under the same pinned
    epoch. Ordering on the frame id alone refused every new frame until the new
    lifetime had counted past the old one's last frame."""
    state = private.home / "gate_state.json"
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    for i in range(1, 5):
        gate.admit(_lifetime_env(i, str(i) * 64, 101.0), now=105.0)

    restarted = AttestationGate(
        AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
    )
    fresh = restarted.admit(_lifetime_env(1, "9" * 64, 120.0), now=125.0)
    assert fresh.nonce == "9" * 64


def test_an_older_lifetime_is_a_rollback_whatever_its_frame_id():
    """The negative control for the fix above: a higher frame id from an earlier
    issue time is an old lifetime's envelope replayed, not progress."""
    gate = _gate()
    gate.admit(_lifetime_env(1, "1" * 64, 120.0), now=125.0)
    with pytest.raises(EnvelopeRejected) as rejection:
        gate.admit(_lifetime_env(9, "9" * 64, 101.0), now=125.0)
    assert rejection.value.reason == "stale-frame"


def test_a_legacy_state_file_still_orders_by_frame_id(private):
    """A state file written before issued_at was recorded keeps its watermark;
    it is never read as 'no state'."""
    state = private.write(private.home / "gate_state.json", '{"last_frame_id": 4}')
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    with pytest.raises(EnvelopeRejected) as rejection:
        gate.admit(_lifetime_env(4, "4" * 64, 120.0), now=125.0)
    assert rejection.value.reason == "stale-frame"
    gate.admit(_lifetime_env(5, "5" * 64, 120.0), now=125.0)
    assert json.loads(state.read_text(encoding="utf-8"))["last_issued_at"] == 120.0


@pytest.mark.parametrize(
    "issued_at",
    ["-1", "true", '"7"', "NaN", "Infinity", "1" + "0" * 400],
    ids=["neg", "bool", "str", "nan", "inf", "too-big-for-a-float"],
)
def test_an_untrusted_issue_time_refuses_to_start(private, issued_at):
    state = private.write(
        private.home / "gate_state.json", f'{{"last_frame_id": 4, "last_issued_at": {issued_at}}}'
    )
    with pytest.raises(GateStateError, match="last_issued_at"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


@_posix_modes
@pytest.mark.parametrize("mode", [0o770, 0o777, 0o1777], ids=["group", "world", "sticky-world"])
def test_a_missing_state_file_in_a_shared_directory_is_not_a_first_start(tmp_path, mode):
    """Whoever can write the directory can delete the file, and a missing file
    would otherwise read as a first start with no watermark."""
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(mode)
    with pytest.raises(GateStateError, match="group/other"):
        AttestationGate(
            AttestationKeyring([_key()]),
            expected_epoch=EPOCH_A,
            state_path=shared / "gate_state.json",
        )


@_windows_only
@pytest.mark.parametrize("grant", [None, "(M)"], ids=["inherited-only", "users-modify"])
def test_a_missing_state_file_in_a_shared_directory_is_not_a_first_start_windows(tmp_path, grant):
    """An existing state directory must itself be owner-only, so even one that
    only inherits entries for SYSTEM and Administrators is refused."""
    shared = tmp_path / "shared"
    shared.mkdir()
    if grant:
        _icacls(shared, "/grant", f"*S-1-5-32-545:{grant}")
    with pytest.raises(GateStateError, match="gate state directory is unsafe"):
        AttestationGate(
            AttestationKeyring([_key()]),
            expected_epoch=EPOCH_A,
            state_path=shared / "gate_state.json",
        )


@_posix_modes
def test_an_existing_state_file_in_a_shared_directory_is_refused(tmp_path):
    """The file itself is owner-only, but another account that can write its
    directory could have swapped an older copy back in: a lower watermark."""
    shared = tmp_path / "shared"
    shared.mkdir()
    state = shared / "gate_state.json"
    state.write_text('{"last_frame_id": 1, "last_issued_at": 101.0}', encoding="utf-8")
    state.chmod(0o600)
    shared.chmod(0o777)
    with pytest.raises(GateStateError, match="group/other"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


@_windows_only
def test_an_existing_state_file_in_a_shared_directory_is_refused_windows(private):
    state = private.write(
        private.home / "gate_state.json", '{"last_frame_id": 1, "last_issued_at": 101.0}'
    )
    AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    _icacls(private.home, "/grant", "*S-1-5-32-545:(M)")
    with pytest.raises(GateStateError, match="gate state directory is unsafe"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


@_posix_modes
def test_a_missing_directory_under_a_shared_parent_is_not_a_first_start(tmp_path):
    """Whoever can write the parent could have renamed the state directory away."""
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(GateStateError, match="moved the watermark away"):
        AttestationGate(
            AttestationKeyring([_key()]),
            expected_epoch=EPOCH_A,
            state_path=shared / "psoperator" / "gate_state.json",
        )


@_windows_only
@pytest.mark.parametrize("grant", ["(AD)", "(DC)", "(WDAC)"], ids=["add", "delete-child", "dac"])
def test_a_missing_directory_under_a_shared_parent_is_not_a_first_start_windows(tmp_path, grant):
    """Administrators stand where root stands on POSIX, so the inheriting temp
    folder is a trusted parent (the control) until another account may change
    its entries."""
    shared = tmp_path / "shared"
    shared.mkdir()
    state = shared / "psoperator" / "gate_state.json"
    AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    _icacls(shared, "/grant", f"*S-1-5-32-545:{grant}")
    with pytest.raises(GateStateError, match="moved the watermark away"):
        AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)


@_posix_modes
def test_the_state_directory_is_created_owner_only(tmp_path):
    """Every missing component is created 0700 rather than under the process
    umask, which may be 002: a group-writable intermediate directory would let
    another account move the state directory below it away and back."""
    old = os.umask(0o002)
    try:
        state = tmp_path / "a" / "b" / "gate_state.json"
        gate = AttestationGate(
            AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state
        )
        gate.admit(_captured_envelopes(1)[0], now=105.0)
    finally:
        os.umask(old)
    for created in (tmp_path / "a", tmp_path / "a" / "b"):
        assert created.stat().st_mode & 0o777 == 0o700, created


@_windows_only
def test_the_state_directory_is_created_owner_only_windows(tmp_path):
    """Every missing component gets an owner-only, protected DACL rather than
    whatever the temp folder would hand down."""
    state = tmp_path / "a" / "b" / "gate_state.json"
    gate = AttestationGate(AttestationKeyring([_key()]), expected_epoch=EPOCH_A, state_path=state)
    gate.admit(_captured_envelopes(1)[0], now=105.0)
    for created in (tmp_path / "a", tmp_path / "a" / "b"):
        winacl.check_owner_only_dir(created)
    os.close(winacl.open_owner_only_for_read(state))


# --- D2: evict nonces by expiry, not by how many admissions happened --------


def test_expired_nonces_are_evicted_by_ttl_not_by_admission_count():
    gate = _gate()
    for envelope in _captured_envelopes(4):
        gate.admit(envelope, now=105.0)
    assert len(gate._seen) == 4, "nothing has expired yet, so nothing may be forgotten"

    later = _signer(_key(), ttl=50.0, nonce="9" * 64).sign(_snapshot(frame_id=9), issued_at=150.0)
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
        AttestationKeyring([_key()]),
        expected_epoch=EPOCH_A,
        record=receipts.append,
        max_nonces=3,
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
