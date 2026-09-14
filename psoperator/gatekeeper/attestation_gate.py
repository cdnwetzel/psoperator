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

import json
import os
import secrets
import stat
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from psoperator.common.attestation import (
    AttestationKeyring,
    UnknownAttestationKey,
    attestation_signature_matches,
)
from psoperator.common.schema import AttestedSnapshot

#: Memory backstop on the remembered-nonce set, nothing more. The primary
#: eviction rule is the TTL (see :meth:`AttestationGate._evict_nonces`).
#:
#: This constant used to carry the claim that "an envelope that old is long past
#: its TTL anyway" — which is false, and falsely reassuring: admission count and
#: elapsed time are unrelated, so a burst can evict a nonce that is still well
#: inside its lifetime. Eviction is now driven by expiry, where it is provably
#: free, and the count only caps memory.
DEFAULT_MAX_NONCES = 4096


class GateStateError(Exception):
    """The persisted gate state could not be read or written.

    Raised rather than tolerated: a gate that cannot recover or record its frame
    watermark silently degrades to the restart behaviour this state file exists
    to remove, and a silent degradation of a fail-closed gate is the failure mode
    this project keeps re-learning.
    """


class EnvelopeRejected(Exception):
    """An observer envelope failed authentication. ``reason`` is a stable slug
    (unknown-key, bad-signature, stale-epoch, not-yet-valid, expired,
    replayed-nonce, stale-frame) so callers and receipts can branch without
    string-matching a message."""

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
        state_path: Path | str | None = None,
    ) -> None:
        self._keyring = keyring
        self._epoch = expected_epoch
        self._clock = clock
        self._record = record or (lambda receipt: None)
        # A non-integer cap (a float like 0.5, or a bool) is a configuration bug:
        # it never trips the OrderedDict eviction cleanly and would silently weaken
        # replay rejection. Require a real int >= 1 (bool is not an int here).
        if isinstance(max_nonces, bool) or not isinstance(max_nonces, int) or max_nonces < 1:
            raise ValueError("max_nonces must be an integer >= 1; a smaller or non-integer "
                             "cap would evict every nonce and disable replay rejection")
        self._max_nonces = max_nonces
        # nonce -> the expires_at of the envelope that burned it, so eviction can
        # be driven by expiry rather than by how many admissions happened since.
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._state_path = Path(state_path) if state_path is not None else None
        self._last_frame_id: int | None = self._load_watermark()

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
        #
        # The durable write goes FIRST, because it is the only step that can fail.
        # If it ran last, a failed write would leave the nonce burned and the epoch
        # pinned for an envelope that was never admitted — and the observer could
        # not even retry it, since its own nonce would now come back as replayed.
        self._advance_watermark(body.snapshot.frame_id)
        if self._epoch is None:
            self._epoch = body.observer_epoch
        self._seen[body.nonce] = body.expires_at
        self._evict_nonces(now)
        return AdmittedFrame(
            key_id=body.key_id,
            observer_epoch=body.observer_epoch,
            frame_hash=body.snapshot.frame_hash,
            nonce=body.nonce,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
        )

    # --- nonce eviction (D2) -------------------------------------------------

    def _evict_nonces(self, now: float) -> None:
        """Forget nonces by expiry first, by count only as a memory backstop.

        Expiry-driven eviction is provably free: ``_verify`` rejects an expired
        envelope *before* it ever consults the nonce set, so a nonce whose
        envelope has expired can no longer be used to replay anything. Dropping
        it costs no replay protection at all.

        The count ceiling has no such guarantee. Evicting by admission count
        assumes count tracks elapsed time, and it does not — a burst evicts
        nonces that are still well inside their lifetime. That is why the ceiling
        is now the backstop rather than the rule, and why reaching it while every
        remembered nonce is still valid is *receipted* instead of done quietly:
        the gate is then in a regime where it cannot promise replay rejection for
        the nonce it just dropped, and an operator should be able to see that.
        """
        for nonce in [n for n, expires_at in self._seen.items() if expires_at <= now]:
            del self._seen[nonce]
        while len(self._seen) > self._max_nonces:
            nonce, expires_at = self._seen.popitem(last=False)
            self._record(
                {
                    "outcome": "nonce-evicted-unexpired",
                    "reason": "max-nonces",
                    "detail": (
                        f"nonce dropped {expires_at - now:.3f}s before its envelope "
                        f"expires; replay of that envelope is no longer refused by "
                        f"the nonce set (the frame watermark still applies)"
                    ),
                    "nonce": nonce,
                    "max_nonces": self._max_nonces,
                    "at": now,
                }
            )

    # --- frame watermark durability (D1) -------------------------------------

    def _load_watermark(self) -> int | None:
        """Restore the last admitted frame id across a restart.

        Without this the watermark is process-local, so a restart disarms the
        stale-frame check entirely and *every* captured envelope still inside its
        TTL replays successfully — not merely the ones a full nonce set had
        evicted. It is the same restart weakness ``observer_epoch`` already
        closes for epoch pinning (CWE-384); the watermark simply never got the
        same treatment.

        A missing file is a genuine first start and yields ``None``. Anything
        else that cannot be trusted raises, because starting with no watermark is
        exactly the state this is here to prevent.

        The file is load-bearing for replay rejection, so it is held to the same
        ownership standard as the attestation key and the IPC secret (R-205): a
        state file another account can rewrite is a state file that can hand the
        gate a *lower* watermark and re-open the very window this closes.
        """
        if self._state_path is None:
            return None
        raw = self._read_state_bytes(self._state_path)
        if raw is None:
            return None
        try:
            state = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise GateStateError(
                f"gate state at {self._state_path} is unreadable: {exc}"
            ) from exc
        if not isinstance(state, dict):
            raise GateStateError(f"gate state at {self._state_path} is not a JSON object")
        watermark = state.get("last_frame_id")
        if isinstance(watermark, bool) or not isinstance(watermark, int) or watermark < 0:
            raise GateStateError(
                f"gate state at {self._state_path} has last_frame_id={watermark!r}; "
                "expected a non-negative integer"
            )
        return watermark

    #: A watermark file is a few dozen bytes. Anything larger is not ours.
    _MAX_STATE_BYTES = 64 * 1024

    def _read_state_bytes(self, path: Path) -> bytes | None:
        """Read the state file, validating the *opened file* rather than the path.

        Checking a path and then opening it are two different files in the
        presence of a race or a symlink, so ownership and file type are asserted
        with ``fstat`` on the descriptor we actually read, and the open refuses to
        traverse a symlink at the final component.
        """
        if os.name == "nt":
            raise GateStateError(
                f"gate state ownership cannot be verified on Windows: {path}. Refusing "
                "to trust an unverified ACL for a file that gates replay rejection."
            )
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None  # genuine first start
        except OSError as exc:
            raise GateStateError(f"gate state at {path} cannot be opened: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise GateStateError(f"gate state at {path} is not a regular file")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise GateStateError(
                    f"gate state at {path} grants group/other permissions "
                    f"(mode {stat.S_IMODE(info.st_mode):04o}); it must be owner-only (0600). "
                    "A writable watermark can be lowered to re-admit captured frames."
                )
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise GateStateError(
                    f"gate state at {path} is owned by uid {info.st_uid}, not this account "
                    f"(uid {os.geteuid()}). Refusing to trust a watermark another account "
                    "can rewrite."
                )
            if info.st_size > self._MAX_STATE_BYTES:
                raise GateStateError(
                    f"gate state at {path} is {info.st_size} bytes; not a watermark file"
                )
            chunks: list[bytes] = []
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                chunks.append(block)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _advance_watermark(self, frame_id: int) -> None:
        """Persist before committing in memory, so a write failure fails closed.

        If the durable record cannot be updated, the envelope is not admitted: a
        gate that keeps admitting while silently losing its watermark is back to
        the restart behaviour above, without anything saying so.
        """
        if self._state_path is not None:
            self._write_state(frame_id)
        self._last_frame_id = frame_id

    def _write_state(self, frame_id: int) -> None:
        """Write owner-only, replace atomically, then make the *replacement*
        durable — not just the bytes.

        ``fsync`` on the file commits its contents; it says nothing about the
        directory entry, so a crash just after admitting could still come back to
        the old watermark and re-open the replay window for exactly the frames
        this admitted. The parent directory is synced too, and a failure there is
        an error rather than a shrug: an undurable watermark is the failure mode
        this whole file exists to remove.

        The temp name is random and created with ``O_EXCL``, so a stale file left
        by a crashed process can neither be silently reused (``O_TRUNC`` would
        have kept its old, possibly loose, mode) nor be a symlink planted for us
        to follow.
        """
        path = self._state_path
        assert path is not None  # guarded by the caller
        payload = json.dumps({"last_frame_id": frame_id}, separators=(",", ":"))
        tmp = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(tmp, flags, 0o600)
            try:
                os.write(fd, payload.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, path)  # atomic: a torn read is never observable
            self._fsync_dir(path.parent)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise GateStateError(f"cannot persist gate state to {path}: {exc}") from exc

    @staticmethod
    def _fsync_dir(directory: Path) -> None:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
