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
    attestation key (``load_attestation_key``). Windows has no mode bits; its
    counterpart is :func:`_load_or_create_secret_windows`, which checks the DACL."""
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
    if os.name == "nt":
        return _load_or_create_secret_windows(target)
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


def _load_or_create_secret_windows(target: Path) -> bytes:
    """Read the secret through a handle whose owner and DACL were checked, or
    create it owner-only in an owner-only directory. Missing directories are
    created owner-only, each relative to a held handle on its parent
    (``winacl.ensure_owner_only_dir``); an existing directory must already be
    owner-only, since the secret is created relative to a verified handle on it."""
    from psoperator.common import winacl

    try:
        fd = winacl.open_owner_only_for_read(target)
    except FileNotFoundError:
        pass
    except winacl.OwnerOnlyError as exc:
        raise PermissionError(
            f"IPC secret is not owner-only: {exc}. Refusing to load a forgeable secret."
        ) from exc
    else:
        with os.fdopen(fd, "rb") as handle:
            secret = handle.read()
        if len(secret) < 32:
            raise ValueError(f"IPC secret at {target} must contain at least 32 bytes")
        return secret
    secret = secrets.token_bytes(32)
    try:
        with winacl.ensure_owner_only_dir(target.parent) as directory:
            try:
                fd = directory.create_file(target.name)
            except FileExistsError:
                return _load_or_create_secret_windows(target)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(secret)
            except BaseException:
                directory.unlink(target.name)
                raise
    except winacl.OwnerOnlyError as exc:
        raise PermissionError(f"cannot create an owner-only IPC secret: {exc}") from exc
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
