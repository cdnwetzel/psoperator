"""Independent capture and perception service with bounded JSON IPC.

The observer owns capture and snapshot construction. Planner-side clients can
request structured observations, but they never receive a capture backend or a
perception provider object. Every successful observation is emitted only inside
a canonical signed attestation envelope.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from pydantic import ValidationError

from psoperator.common.attestation import SnapshotSigner
from psoperator.common.ipc import IPCServer
from psoperator.common.schema import (
    OBSERVER_PROTOCOL_VERSION,
    ObserverHealth,
    ObserverRequest,
)
from psoperator.config import PSOperatorConfig
from psoperator.perception.capture import Frame, MSSCapture, ScreenCapture
from psoperator.perception.snapshot import SnapshotBuilder

MAX_OBSERVER_ERROR_CHARS = 512
OBSERVER_UNAVAILABLE_PREFIX = "observer unavailable: "


class ObserverService:
    """Own one capture backend and publish complete structured observations."""

    def __init__(
        self,
        capture: ScreenCapture,
        signer: SnapshotSigner,
        snapshot_builder: SnapshotBuilder | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._capture = capture
        self._signer = signer
        self._snapshots = snapshot_builder or SnapshotBuilder()
        self._clock = clock
        self._started_at = clock()
        self._last_success_at: float | None = None
        self._last_sequence = 0
        self._failures = 0
        self._error = ""
        self._closed = False
        self._backend = type(capture).__name__[:128] or "unknown"

    def health(self) -> ObserverHealth:
        if self._closed:
            status = "stopped"
        elif self._failures:
            status = "degraded"
        else:
            status = "ready"
        return ObserverHealth(
            status=status,
            backend=self._backend,
            started_at=self._started_at,
            last_success_at=self._last_success_at,
            last_sequence=self._last_sequence,
            consecutive_failures=self._failures,
            error=self._error,
            attestation_key_id=self._signer.key_id,
            observer_epoch=self._signer.observer_epoch,
        )

    def _response(self, **payload: object) -> dict:
        return {
            "protocol_version": OBSERVER_PROTOCOL_VERSION,
            **payload,
        }

    def _failure(self, message: str) -> dict:
        error = message[:MAX_OBSERVER_ERROR_CHARS]
        return self._response(
            ok=False,
            error=error,
            health=self.health().model_dump(mode="json"),
        )

    def _observe(self) -> dict:
        if self._closed:
            return self._failure("observer unavailable: service is stopped")
        try:
            source = self._capture.grab()
            sequence = self._last_sequence + 1
            # Re-hash the pixels here instead of trusting a capture backend's
            # claimed digest; the observer owns the evidence it publishes.
            frame = Frame.from_image(sequence, source.image, captured_at=self._clock())
            snapshot = self._snapshots.build(frame)
            if (
                snapshot.frame_id != frame.frame_id
                or snapshot.captured_at != frame.captured_at
                or snapshot.frame_hash != frame.sha256
                or snapshot.screen_size != frame.image.size
            ):
                raise ValueError("snapshot metadata does not match the captured frame")
            attestation = self._signer.sign(snapshot, issued_at=self._clock())
        except Exception as exc:
            self._failures += 1
            error_budget = MAX_OBSERVER_ERROR_CHARS - len(OBSERVER_UNAVAILABLE_PREFIX)
            self._error = f"{type(exc).__name__}: {exc}"[:error_budget]
            return self._failure(f"{OBSERVER_UNAVAILABLE_PREFIX}{self._error}")

        self._last_sequence = sequence
        self._last_success_at = attestation.body.issued_at
        self._failures = 0
        self._error = ""
        return self._response(
            ok=True,
            attestation=attestation.model_dump(mode="json"),
            health=self.health().model_dump(mode="json"),
        )

    def handle(self, payload: dict) -> dict:
        try:
            request = ObserverRequest.model_validate(payload)
        except ValidationError as exc:
            return self._failure(f"invalid observer request: {exc}")
        if request.op == "health":
            return self._response(ok=True, health=self.health().model_dump(mode="json"))
        return self._observe()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._capture.close()


def build_capture(config: PSOperatorConfig, backend: str | None = None) -> ScreenCapture:
    """Build the selected capture backend in the observer process."""
    selected = backend or config.capture_backend
    if selected == "mss":
        return MSSCapture(config.monitor)
    if selected == "uvc":
        from psoperator.perception.capture_uvc import UVCCapture

        return UVCCapture(
            device_index=config.uvc_device_index,
            width=config.uvc_width,
            height=config.uvc_height,
        )
    raise ValueError(f"unknown capture backend {selected!r}")


def serve(
    host: str,
    port: int,
    capture: ScreenCapture,
    signer: SnapshotSigner,
    snapshot_builder: SnapshotBuilder | None = None,
) -> None:
    """Serve until interrupted, always releasing the capture backend."""
    service = ObserverService(capture, signer, snapshot_builder)
    try:
        IPCServer(host, port).serve_forever(service.handle)
    finally:
        service.close()
