"""Bounded JSON transport and authenticated executor service."""

from __future__ import annotations

import socket
import time

import pytest

from psoperator.common.auth import sign_payload
from psoperator.common.ipc import MAX_MESSAGE_BYTES, IPCError, recv_json, send_json
from psoperator.gatekeeper.executor import DryRunExecutor
from psoperator.services.executor import ExecutorService


def test_json_socket_round_trip():
    left, right = socket.socketpair()
    try:
        send_json(left, {"hello": ["world", 1]})
        assert recv_json(right) == {"hello": ["world", 1]}
    finally:
        left.close()
        right.close()


def test_oversized_message_is_rejected_before_send():
    left, right = socket.socketpair()
    try:
        with pytest.raises(IPCError, match="exceeds"):
            send_json(left, {"payload": "x" * MAX_MESSAGE_BYTES})
    finally:
        left.close()
        right.close()


def _request(secret: bytes, nonce: str = "n1", issued_at: float | None = None):
    body = {
        "action": {"action": "wait", "seconds": 0.001, "frame_id": 1},
        "issued_at": time.time() if issued_at is None else issued_at,
        "nonce": nonce,
    }
    return {"body": body, "signature": sign_payload(secret, body)}


def test_executor_accepts_valid_signature_and_rejects_replay():
    secret = b"s" * 32
    service = ExecutorService(DryRunExecutor(), secret)
    message = _request(secret)
    assert service.handle(message)["ok"]
    replay = service.handle(message)
    assert not replay["ok"] and "replayed" in replay["error"]


def test_executor_rejects_bad_signature_and_stale_request():
    secret = b"s" * 32
    service = ExecutorService(DryRunExecutor(), secret)
    bad = _request(secret)
    bad["signature"] = "0" * 64
    assert not service.handle(bad)["ok"]
    stale = service.handle(_request(secret, nonce="n2", issued_at=time.time() - 60))
    assert not stale["ok"] and "stale" in stale["error"]
