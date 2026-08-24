"""Authenticated executor proxy used by the process-separated gatekeeper."""

from __future__ import annotations

import time
import uuid

from psoperator.common.auth import sign_payload
from psoperator.common.ipc import request
from psoperator.runtime.actions import Action


class RemoteExecutor:
    name = "remote"

    def __init__(self, host: str, port: int, secret: bytes, timeout_s: float = 10.0) -> None:
        self._host = host
        self._port = port
        self._secret = secret
        self._timeout = timeout_s

    def execute(self, action: Action) -> str:
        body = {
            "action": action.to_dict(),
            "issued_at": time.time(),
            "nonce": uuid.uuid4().hex,
        }
        response = request(
            self._host,
            self._port,
            {"body": body, "signature": sign_payload(self._secret, body)},
            timeout=self._timeout,
        )
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "remote executor rejected request"))
        backend = str(response.get("executor", "remote"))
        self.name = "dry-run" if backend == "dry-run" else f"remote:{backend}"
        return str(response.get("outcome", "remote executor completed"))
