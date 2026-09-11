"""R-203 at the trust boundary — the gatekeeper *service* authenticates the
observer envelope a planner sends before anything downstream trusts it.

`test_attestation_gate.py` proves the gate's logic in isolation; these prove it
is actually in the path: a forged, unknown-key, stale-epoch, or expired envelope
is refused by `GatekeeperService.handle`, `request_action` is never reached, and
the verdict is receipted. The positive control proves a genuine envelope still
gets through to the gatekeeper.
"""

from __future__ import annotations

from types import SimpleNamespace

from psoperator.common.attestation import AttestationKey, AttestationKeyring, SnapshotSigner
from psoperator.common.schema import PerceptionSnapshot
from psoperator.gatekeeper.attestation_gate import AttestationGate
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.services.gatekeeper import GatekeeperService

KEY_ID = "observer-2026-09"
EPOCH_A = "a" * 64
EPOCH_B = "b" * 64
NOW = 105.0


def _key(secret: bytes = b"s" * 32, key_id: str = KEY_ID) -> AttestationKey:
    return AttestationKey(key_id, secret, created_at=90.0)


def _snapshot() -> PerceptionSnapshot:
    return PerceptionSnapshot(
        frame_id=7, captured_at=100.0, frame_hash="f" * 64, screen_size=(80, 60)
    )


def _envelope(key: AttestationKey, *, epoch: str = EPOCH_A, ttl: float = 10.0,
              nonce: str = "1" * 64, issued_at: float = 101.0):
    signer = SnapshotSigner(key, ttl_s=ttl, observer_epoch=epoch, nonce_factory=lambda: nonce)
    return signer.sign(_snapshot(), issued_at=issued_at)


def _request(envelope):
    return {
        "attestation": envelope.model_dump(mode="json"),
        "action": {"action": "wait", "seconds": 0.001, "frame_id": 7},
        "context": {},
    }


class _FakeGatekeeper:
    """Records whether request_action was reached; the auth gate must run first."""

    def __init__(self) -> None:
        self.calls: list = []

    def request_action(self, action, frame, context, snapshot):
        self.calls.append((action, frame, snapshot))
        return SimpleNamespace(
            kind=SimpleNamespace(value="APPROVED_AUTO"),
            action=SimpleNamespace(to_dict=lambda: {"action": "wait"}),
            risk=None, approver="gatekeeper", reason="ok", outcome="dry-run", approved=True,
        )


def _service(*, keyring=None, epoch=EPOCH_A, receipts=None):
    kr = keyring or AttestationKeyring([_key()])
    record = receipts.append if receipts is not None else None
    gate = AttestationGate(kr, expected_epoch=epoch, clock=lambda: NOW, record=record)
    gk = _FakeGatekeeper()
    return GatekeeperService(gk, FreshnessTracker(), gate), gk


# --- positive control -------------------------------------------------------


def test_a_genuine_envelope_reaches_the_gatekeeper():
    service, gk = _service()
    resp = service.handle(_request(_envelope(_key())))
    assert resp["ok"] is True
    assert len(gk.calls) == 1  # request_action was reached only after authentication


# --- the attacks are refused at the door, request_action never reached ------


def test_a_forged_signature_is_refused_before_the_gatekeeper():
    # Signed with the wrong secret; keyring holds the real one.
    service, gk = _service()
    resp = service.handle(_request(_envelope(_key(secret=b"x" * 32))))
    assert resp["ok"] is False and resp["reason"] == "bad-signature"
    assert gk.calls == []  # the forgery never reached request_action


def test_an_unknown_key_is_refused():
    service, gk = _service()
    resp = service.handle(_request(_envelope(_key(key_id="ghost-key"))))
    assert resp["ok"] is False and resp["reason"] == "unknown-key"
    assert gk.calls == []


def test_a_stale_epoch_envelope_is_refused():
    service, gk = _service(epoch=EPOCH_A)
    resp = service.handle(_request(_envelope(_key(), epoch=EPOCH_B)))
    assert resp["ok"] is False and resp["reason"] == "stale-epoch"
    assert gk.calls == []


def test_an_expired_envelope_is_refused():
    service, gk = _service()  # gate clock = 105
    resp = service.handle(_request(_envelope(_key(), ttl=1.0, issued_at=101.0)))  # expires 102
    assert resp["ok"] is False and resp["reason"] == "expired"
    assert gk.calls == []


def test_a_replayed_envelope_is_refused():
    service, gk = _service()
    env = _envelope(_key(), nonce="2" * 64)
    assert service.handle(_request(env))["ok"] is True   # first time through
    resp = service.handle(_request(env))                  # same envelope again
    assert resp["ok"] is False and resp["reason"] == "replayed-nonce"
    assert len(gk.calls) == 1  # only the first reached the gatekeeper


# --- receipting -------------------------------------------------------------


def test_every_verdict_at_the_boundary_is_receipted():
    receipts: list[dict] = []
    service, _ = _service(receipts=receipts)
    service.handle(_request(_envelope(_key())))                       # admitted
    service.handle(_request(_envelope(_key(secret=b"x" * 32))))       # rejected
    assert [r["outcome"] for r in receipts] == ["admitted", "rejected"]
    assert receipts[-1]["reason"] == "bad-signature"
    assert receipts[0]["frame_id"] == 7  # the receipt binds the frame it authenticated
