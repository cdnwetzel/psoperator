"""R-203 — the gatekeeper's authentication of observer envelopes.

`attestation_signature_matches` proves an envelope was signed by a known key and
nothing more; its docstring hands the rest here: "R-203 owns policy and replay
checks." :class:`AttestationGate` is that owner. It admits an
:class:`~psoperator.common.schema.AttestedSnapshot` only if it survives every
check a compromised or injected planner would need to defeat, and it receipts the
verdict either way — an admitted frame or a named refusal.

The checks, in fail-closed order (most fundamental first, so a forged envelope
never reaches the replay bookkeeping):

1. **unknown-key** — the key id is not in the registered keyring.
2. **bad-signature** — the signature does not match that key.
3. **stale-epoch** — the observer epoch is not the one this gate is pinned to. An
   observer service has one epoch per lifetime; an envelope from another epoch is
   a rollback to (or a fork of) a different observer session. With no epoch
   configured, the gate trusts the first fully-admitted envelope's epoch and
   refuses the rest — a later trust decision, never automatic.
4. **not-yet-valid / expired** — now is outside ``[issued_at, expires_at]``.
5. **replayed-nonce** — this nonce was already admitted under the pinned epoch.
6. **stale-frame** — the snapshot frame id does not advance past the last admitted
   (an older frame replayed after a newer one — a rollback).

Epoch pinning and nonce recording happen only after *every* check passes, so a
rejected envelope can neither pin an epoch nor consume a nonce.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from psoperator.common.attestation import (
    AttestationKeyring,
    UnknownAttestationKey,
    attestation_signature_matches,
)
from psoperator.common.schema import AttestedSnapshot

#: Bound on the remembered-nonce set per pinned epoch. Nonces older than this many
#: admissions are evicted; an envelope that old is long past its TTL anyway.
DEFAULT_MAX_NONCES = 4096


class EnvelopeRejected(Exception):
    """An observer envelope failed authentication. ``reason`` is a stable slug
    (unknown-key, bad-signature, stale-epoch, not-yet-valid, expired,
    replayed-nonce) so callers and receipts can branch without string-matching a
    message."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class AdmittedFrame:
    """The binding an admitted envelope authorizes: which observer (key + epoch)
    attested which frame, under which one-time nonce and lifetime."""

    key_id: str
    observer_epoch: str
    frame_hash: str
    nonce: str
    issued_at: float
    expires_at: float


class AttestationGate:
    def __init__(
        self,
        keyring: AttestationKeyring,
        *,
        expected_epoch: str | None = None,
        clock: Callable[[], float] = time.time,
        record: Callable[[dict], None] | None = None,
        max_nonces: int = DEFAULT_MAX_NONCES,
    ) -> None:
        self._keyring = keyring
        self._epoch = expected_epoch
        self._clock = clock
        self._record = record or (lambda receipt: None)
        self._max_nonces = max_nonces
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._last_frame_id: int | None = None

    @property
    def pinned_epoch(self) -> str | None:
        return self._epoch

    def admit(self, envelope: AttestedSnapshot, *, now: float | None = None) -> AdmittedFrame:
        """Authenticate ``envelope`` and return the frame it authorizes, or raise
        :class:`EnvelopeRejected`. Records exactly one receipt per call."""
        moment = self._clock() if now is None else now
        body = envelope.body
        try:
            frame = self._verify(envelope, moment)
        except EnvelopeRejected as rejection:
            self._record(
                {
                    "outcome": "rejected",
                    "reason": rejection.reason,
                    "detail": rejection.detail,
                    "key_id": body.key_id,
                    "observer_epoch": body.observer_epoch,
                    "nonce": body.nonce,
                    "frame_id": body.snapshot.frame_id,
                    "frame_hash": body.snapshot.frame_hash,
                    "at": moment,
                }
            )
            raise
        self._record(
            {
                "outcome": "admitted",
                "reason": None,
                "key_id": frame.key_id,
                "observer_epoch": frame.observer_epoch,
                "nonce": frame.nonce,
                "frame_id": body.snapshot.frame_id,
                "frame_hash": frame.frame_hash,
                "at": moment,
            }
        )
        return frame

    def _verify(self, envelope: AttestedSnapshot, now: float) -> AdmittedFrame:
        body = envelope.body
        try:
            key = self._keyring.require(body.key_id)
        except UnknownAttestationKey:
            raise EnvelopeRejected("unknown-key", body.key_id) from None
        if not attestation_signature_matches(key, envelope):
            raise EnvelopeRejected("bad-signature", body.key_id)
        if self._epoch is not None and body.observer_epoch != self._epoch:
            raise EnvelopeRejected(
                "stale-epoch", f"expected {self._epoch[:12]}…, got {body.observer_epoch[:12]}…"
            )
        if now < body.issued_at:
            raise EnvelopeRejected("not-yet-valid", f"now {now} < issued_at {body.issued_at}")
        if now > body.expires_at:
            raise EnvelopeRejected("expired", f"now {now} > expires_at {body.expires_at}")
        if body.nonce in self._seen:
            raise EnvelopeRejected("replayed-nonce", body.nonce)
        # Observer frame ids strictly increase; a non-increasing one is an older
        # frame replayed after a newer (still within its TTL, a fresh nonce, so
        # the checks above pass). Reject the rollback at this boundary rather than
        # leaving it to freshness downstream.
        if self._last_frame_id is not None and body.snapshot.frame_id <= self._last_frame_id:
            raise EnvelopeRejected(
                "stale-frame",
                f"frame {body.snapshot.frame_id} does not advance past last admitted "
                f"{self._last_frame_id}",
            )

        # Every check passed — only now commit state, so a rejected envelope can
        # neither pin an epoch (trust-on-first-use), burn a nonce, nor advance the
        # frame watermark.
        if self._epoch is None:
            self._epoch = body.observer_epoch
        self._seen[body.nonce] = None
        while len(self._seen) > self._max_nonces:
            self._seen.popitem(last=False)
        self._last_frame_id = body.snapshot.frame_id
        return AdmittedFrame(
            key_id=body.key_id,
            observer_epoch=body.observer_epoch,
            frame_hash=body.snapshot.frame_hash,
            nonce=body.nonce,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
        )
