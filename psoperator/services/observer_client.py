"""Planner-safe client for the independent observer service."""

from __future__ import annotations

from pydantic import ValidationError

from psoperator.common.ipc import IPCError
from psoperator.common.ipc import request as ipc_request
from psoperator.common.schema import (
    OBSERVER_PROTOCOL_VERSION,
    AttestedSnapshot,
    ObserverHealth,
)


class ObserverUnavailable(RuntimeError):
    """Raised when the observer cannot return a complete, valid snapshot."""

    def __init__(self, message: str, health: ObserverHealth | None = None) -> None:
        super().__init__(message)
        self.health = health


class ObserverClient:
    """Validated client exposing only structured snapshots and health."""

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    def _call(self, op: str) -> dict:
        try:
            response = ipc_request(
                self._host,
                self._port,
                {"version": OBSERVER_PROTOCOL_VERSION, "op": op},
                timeout=self._timeout,
            )
        except (IPCError, OSError) as exc:
            raise ObserverUnavailable(f"observer unavailable: {exc}") from exc
        if response.get("protocol_version") != OBSERVER_PROTOCOL_VERSION:
            if response.get("ok") is False and isinstance(response.get("error"), str):
                raise ObserverUnavailable(f"observer service error: {response['error']}")
            raise ObserverUnavailable("observer returned an unsupported protocol version")
        return response

    @staticmethod
    def _health(response: dict) -> ObserverHealth | None:
        try:
            return ObserverHealth.model_validate(response["health"])
        except (KeyError, ValidationError):
            return None

    def health(self) -> ObserverHealth:
        response = self._call("health")
        health = self._health(response)
        if not response.get("ok") or health is None:
            raise ObserverUnavailable(str(response.get("error", "invalid health response")), health)
        return health

    def observe(self) -> AttestedSnapshot:
        response = self._call("observe")
        health = self._health(response)
        if not response.get("ok"):
            raise ObserverUnavailable(str(response.get("error", "observation failed")), health)
        if health is None:
            raise ObserverUnavailable("observer returned invalid health")
        try:
            attestation = AttestedSnapshot.model_validate(response["attestation"])
        except (KeyError, ValidationError) as exc:
            raise ObserverUnavailable("observer returned an invalid attestation", health) from exc
        if (
            attestation.body.key_id != health.attestation_key_id
            or attestation.body.observer_epoch != health.observer_epoch
        ):
            raise ObserverUnavailable("observer attestation does not match service health", health)
        return attestation
