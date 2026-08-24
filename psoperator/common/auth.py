"""HMAC authentication for the gatekeeper-to-executor IPC hop."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any


def load_or_create_secret(path: Path) -> bytes:
    target = Path(path)
    if target.exists():
        secret = target.read_bytes()
        if len(secret) < 32:
            raise ValueError(f"IPC secret at {target} must contain at least 32 bytes")
        return secret
    target.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(32)
    try:
        with target.open("xb") as handle:
            handle.write(secret)
        os.chmod(target, 0o600)
    except FileExistsError:
        return load_or_create_secret(target)
    return secret


def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_payload(secret: bytes, payload: dict[str, Any]) -> str:
    return hmac.new(secret, canonical_payload(payload), hashlib.sha256).hexdigest()


def signature_is_valid(secret: bytes, payload: dict[str, Any], signature: str) -> bool:
    return hmac.compare_digest(sign_payload(secret, payload), signature)
