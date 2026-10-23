"""HMAC authentication for the gatekeeper-to-executor IPC hop."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any


def _assert_owner_only(target: Path) -> None:
    """Fail closed unless the secret is owner-only. A pre-existing secret that is
    group/world-accessible — or owned by another account — could be read by the
    untrusted planner and used to forge executor requests, so we refuse to load it
    rather than trust it. This mirrors the R-205 posture already enforced on the
    attestation key (``load_attestation_key``): on an unclaimed platform (Windows,
    unverified NTFS ACL) we refuse rather than trust it."""
    if os.name == "nt":
        raise PermissionError(
            f"IPC secret owner-only enforcement is not implemented on Windows: {target}. "
            "Refusing to load rather than trust an unverified ACL."
        )
    info = target.stat()
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(
            f"IPC secret at {target} grants group/other permissions "
            f"(mode {stat.S_IMODE(info.st_mode):04o}); it must be owner-only (0600). "
            "Refusing to load a forgeable secret."
        )
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise PermissionError(
            f"IPC secret at {target} is owned by uid {info.st_uid}, not this account "
            f"(uid {os.geteuid()}). Refusing to load a secret another account can rewrite."
        )


def load_or_create_secret(path: Path) -> bytes:
    target = Path(path)
    if target.exists():
        _assert_owner_only(target)
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
