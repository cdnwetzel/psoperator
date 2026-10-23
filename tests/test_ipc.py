"""Bounded JSON transport and authenticated executor service."""

from __future__ import annotations

import os
import socket
import stat
import threading
import time

import pytest

from psoperator.common.auth import load_or_create_secret, sign_payload
from psoperator.common.ipc import MAX_MESSAGE_BYTES, IPCError, IPCServer, recv_json, send_json
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


# --- the IPC secret is owner-only (fail closed) -----------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only secret files")
def test_a_group_or_world_readable_ipc_secret_is_refused(tmp_path):
    # A pre-existing secret the untrusted planner account could read would let it
    # forge executor requests. Loading such a secret is refused, not trusted
    # (Copilot, psoperator #10). The freshly-created secret is owner-only.
    path = tmp_path / "ipc.secret"
    secret = load_or_create_secret(path)  # creates it 0600
    assert len(secret) >= 32
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for mode in (0o640, 0o644, 0o604, 0o660):
        path.chmod(mode)
        with pytest.raises(PermissionError, match="owner-only"):
            load_or_create_secret(path)
    path.chmod(0o600)
    assert load_or_create_secret(path) == secret  # restored -> loads again


# --- loopback binds IPv6 as well as IPv4 ------------------------------------


def _ipv6_loopback_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        s.bind(("::1", 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _free_ipv6_loopback_port() -> int:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.bind(("::1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="no IPv6 loopback on this host")
def test_ipc_server_binds_and_serves_over_ipv6_loopback():
    # serve_forever selects the socket family from the host; a regression to a
    # hardcoded AF_INET would fail to bind "::1". Run the real server on an IPv6
    # loopback port and round-trip one request end to end (Copilot, psoperator #10).
    port = _free_ipv6_loopback_port()
    server = IPCServer("::1", port)
    t = threading.Thread(
        target=server.serve_forever,
        args=(lambda req: {"ok": True, "echo": req},),
        daemon=True,  # serve_forever loops; the daemon thread ends with the test
    )
    t.start()

    deadline = time.time() + 5
    while True:
        try:
            conn = socket.create_connection(("::1", port), timeout=1)
            break
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(0.02)
    with conn:
        send_json(conn, {"ping": 1})
        assert recv_json(conn) == {"ok": True, "echo": {"ping": 1}}
