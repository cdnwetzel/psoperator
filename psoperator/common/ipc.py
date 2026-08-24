"""Length-prefixed JSON IPC for optional process-separated operation."""

from __future__ import annotations

import json
import socket
import struct
from collections.abc import Callable
from typing import Any

MAX_MESSAGE_BYTES = 4 * 1024 * 1024


class IPCError(RuntimeError):
    """Raised for malformed, oversized, or incomplete IPC messages."""


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise IPCError("peer closed before the complete message arrived")
        chunks.extend(chunk)
    return bytes(chunks)


def send_json(sock: socket.socket, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        raise IPCError(f"message exceeds {MAX_MESSAGE_BYTES} bytes")
    sock.sendall(struct.pack(">I", len(body)) + body)


def recv_json(sock: socket.socket) -> dict[str, Any]:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_MESSAGE_BYTES:
        raise IPCError(f"declared message exceeds {MAX_MESSAGE_BYTES} bytes")
    try:
        payload = json.loads(_recv_exact(sock, length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IPCError(f"invalid JSON message: {exc}") from exc
    if not isinstance(payload, dict):
        raise IPCError("top-level IPC message must be an object")
    return payload


def request(host: str, port: int, payload: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_json(sock, payload)
        return recv_json(sock)


class IPCServer:
    """Small synchronous loopback server used by the isolated service mode."""

    def __init__(self, host: str, port: int) -> None:
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("IPC services must bind to loopback")
        self.host = host
        self.port = port

    def serve_forever(self, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(16)
            while True:
                conn, _ = server.accept()
                with conn:
                    try:
                        response = handler(recv_json(conn))
                    except Exception as exc:  # fail closed at the boundary
                        response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                    send_json(conn, response)
