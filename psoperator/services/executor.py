"""Authenticated executor service; the only process that injects input."""

from __future__ import annotations

import json
import time

from psoperator.common.auth import signature_is_valid
from psoperator.common.ipc import IPCServer
from psoperator.gatekeeper.executor import DryRunExecutor, Executor, PynputExecutor
from psoperator.gatekeeper.executor_ch9329 import CH9329Executor
from psoperator.runtime.actions import parse_action


def build_executor(backend: str, *, port: str, baudrate: int) -> Executor:
    if backend == "dryrun":
        return DryRunExecutor()
    if backend == "pynput":
        return PynputExecutor()
    if backend == "ch9329":
        return CH9329Executor(port=port, baudrate=baudrate)
    raise ValueError(f"unknown executor backend {backend!r}")


class ExecutorService:
    def __init__(self, executor: Executor, secret: bytes, max_age_s: float = 15.0) -> None:
        self._executor = executor
        self._secret = secret
        self._max_age = max_age_s
        self._seen_nonces: set[str] = set()

    def handle(self, request: dict) -> dict:
        body = request.get("body")
        signature = request.get("signature")
        if not isinstance(body, dict) or not isinstance(signature, str):
            return {"ok": False, "error": "missing authenticated request envelope"}
        if not signature_is_valid(self._secret, body, signature):
            return {"ok": False, "error": "invalid executor request signature"}
        nonce = body.get("nonce")
        issued_at = body.get("issued_at")
        if not isinstance(nonce, str) or nonce in self._seen_nonces:
            return {"ok": False, "error": "missing or replayed nonce"}
        if not isinstance(issued_at, (int, float)) or abs(time.time() - issued_at) > self._max_age:
            return {"ok": False, "error": "stale executor request"}
        self._seen_nonces.add(nonce)
        if len(self._seen_nonces) > 10_000:
            self._seen_nonces.clear()
            self._seen_nonces.add(nonce)
        try:
            action = parse_action(json.dumps(body["action"]))
            return {
                "ok": True,
                "executor": self._executor.name,
                "outcome": self._executor.execute(action),
            }
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def serve(host: str, port: int, executor: Executor, secret: bytes) -> None:
    IPCServer(host, port).serve_forever(ExecutorService(executor, secret).handle)
