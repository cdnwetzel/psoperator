"""Snapshot signing keys and canonical observer attestation envelopes."""

from __future__ import annotations

import base64
import json
import math
import os
import re
import secrets
import stat
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from psoperator.common.auth import sign_payload, signature_is_valid
from psoperator.common.schema import (
    ATTESTATION_KEY_ID_PATTERN,
    LOWER_SHA256_PATTERN,
    MAX_ATTESTATION_KEY_ID_CHARS,
    MAX_SNAPSHOT_TTL_SECONDS,
    SNAPSHOT_SIGNATURE_VERSION,
    AttestedSnapshot,
    PerceptionSnapshot,
    SnapshotAttestationBody,
)

ATTESTATION_KEY_BYTES = 32
ATTESTATION_KEY_FILE_VERSION = 1
MAX_ATTESTATION_KEY_FILE_BYTES = 4096


class AttestationKeyError(ValueError):
    """Raised when key material is absent, unsafe, malformed, or ambiguous."""


class UnknownAttestationKey(AttestationKeyError):
    """Raised when an envelope names a key outside the explicit trusted set."""


class _AttestationKeyFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1]
    key_id: str = Field(
        min_length=1,
        max_length=MAX_ATTESTATION_KEY_ID_CHARS,
        pattern=ATTESTATION_KEY_ID_PATTERN,
    )
    created_at: float = Field(ge=0)
    secret_b64: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def _valid_material(self) -> "_AttestationKeyFile":
        if not math.isfinite(self.created_at):
            raise ValueError("key creation time must be finite")
        try:
            secret = base64.b64decode(self.secret_b64, validate=True)
        except ValueError as exc:
            raise ValueError("key secret must be valid base64") from exc
        if len(secret) != ATTESTATION_KEY_BYTES:
            raise ValueError(f"key secret must decode to exactly {ATTESTATION_KEY_BYTES} bytes")
        return self


@dataclass(frozen=True)
class AttestationKey:
    """Validated in-memory HMAC key; the secret is deliberately omitted from repr."""

    key_id: str
    secret: bytes = field(repr=False)
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if re.fullmatch(ATTESTATION_KEY_ID_PATTERN, self.key_id) is None:
            raise AttestationKeyError("invalid attestation key id")
        if len(self.secret) != ATTESTATION_KEY_BYTES:
            raise AttestationKeyError(
                f"attestation key must contain exactly {ATTESTATION_KEY_BYTES} bytes"
            )
        if not math.isfinite(self.created_at) or self.created_at < 0:
            raise AttestationKeyError(
                "attestation key creation time must be finite and nonnegative"
            )


def _key_file(key: AttestationKey) -> _AttestationKeyFile:
    return _AttestationKeyFile(
        format_version=ATTESTATION_KEY_FILE_VERSION,
        key_id=key.key_id,
        created_at=key.created_at,
        secret_b64=base64.b64encode(key.secret).decode("ascii"),
    )


def provision_attestation_key(
    path: Path,
    key_id: str,
    *,
    clock: Callable[[], float] = time.time,
) -> AttestationKey:
    """Create one owner-only key file without ever replacing an existing path."""
    if os.name == "nt":
        raise AttestationKeyError(
            "secure Windows attestation-key ACL provisioning is not implemented"
        )
    key = AttestationKey(key_id, secrets.token_bytes(ATTESTATION_KEY_BYTES), clock())
    target = Path(path)
    encoded = (
        json.dumps(_key_file(key).model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    # Anchor the create (and any cleanup) to a validated directory fd, using the
    # bare filename with dir_fd=. An ancestor-directory swap between the check
    # and the create then cannot redirect where the key file lands.
    dir_fd = _open_owner_only_dir(target.parent)
    try:
        try:
            fd = os.open(target.name, flags, 0o600, dir_fd=dir_fd)
        except FileExistsError as exc:
            raise AttestationKeyError(
                f"refusing to overwrite attestation key file: {target}"
            ) from exc
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write while provisioning attestation key")
                view = view[written:]
            os.fsync(fd)
        except Exception:
            os.close(fd)
            os.unlink(target.name, dir_fd=dir_fd)
            raise
        else:
            os.close(fd)
    finally:
        os.close(dir_fd)
    return key


def _open_owner_only_dir(path: Path) -> int:
    """Open a real, owner-only directory as a TOCTOU-safe fd, so a create/unlink
    anchored to it (dir_fd=) cannot be redirected by an ancestor-directory swap.
    Mirrors the file reader's discipline: lstat, O_NOFOLLOW open, then re-check
    dev/ino, type, mode, and ownership on the fd itself. Caller must close it."""
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise AttestationKeyError(
            f"attestation key directory must be pre-provisioned owner-only: {path}"
        ) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise AttestationKeyError(f"attestation key directory must be a real directory: {path}")
    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    try:
        dir_fd = os.open(path, flags)
    except OSError as exc:
        raise AttestationKeyError(
            f"cannot safely open attestation key directory: {path}"
        ) from exc
    try:
        info = os.fstat(dir_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise AttestationKeyError(f"attestation key directory is not a directory: {path}")
        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise AttestationKeyError(f"attestation key directory changed while opening: {path}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise AttestationKeyError(
                f"attestation key directory must not grant group/other permissions: {path}"
            )
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise AttestationKeyError(
                f"attestation key directory must be owned by this account: {path}"
            )
    except Exception:
        os.close(dir_fd)
        raise
    return dir_fd


def _read_owner_only_file(path: Path) -> bytes:
    if os.name == "nt":
        raise AttestationKeyError(
            "secure Windows attestation-key ACL verification is not implemented"
        )
    target = Path(path)
    try:
        before = target.lstat()
    except FileNotFoundError as exc:
        raise AttestationKeyError(f"attestation key file does not exist: {target}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise AttestationKeyError(f"attestation key file must not be a symlink: {target}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise AttestationKeyError(f"cannot safely open attestation key file: {target}") from exc
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode):
            raise AttestationKeyError(f"attestation key path is not a regular file: {target}")
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise AttestationKeyError(f"attestation key file changed while opening: {target}")
        if stat.S_IMODE(current.st_mode) & 0o077:
            raise AttestationKeyError(
                f"attestation key file must not grant group/other permissions: {target}"
            )
        if hasattr(os, "geteuid") and current.st_uid != os.geteuid():
            raise AttestationKeyError(
                f"attestation key file must be owned by this account: {target}"
            )
        data = os.read(fd, MAX_ATTESTATION_KEY_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_ATTESTATION_KEY_FILE_BYTES:
        raise AttestationKeyError(f"attestation key file exceeds size limit: {target}")
    return data


def load_attestation_key(path: Path) -> AttestationKey:
    """Load one strictly encoded owner-only signing or verification key."""
    data = _read_owner_only_file(Path(path))
    try:
        material = _AttestationKeyFile.model_validate_json(data)
        secret = base64.b64decode(material.secret_b64, validate=True)
    except (ValidationError, ValueError) as exc:
        raise AttestationKeyError(f"invalid attestation key file: {path}") from exc
    return AttestationKey(material.key_id, secret, material.created_at)


class AttestationKeyring:
    """Explicit trusted-key set used to make rotation and retirement deliberate."""

    def __init__(self, keys: Iterable[AttestationKey]) -> None:
        by_id: dict[str, AttestationKey] = {}
        for key in keys:
            if key.key_id in by_id:
                raise AttestationKeyError(f"duplicate attestation key id: {key.key_id}")
            by_id[key.key_id] = key
        self._keys = by_id

    @classmethod
    def from_paths(cls, paths: Iterable[Path]) -> "AttestationKeyring":
        return cls(load_attestation_key(path) for path in paths)

    def require(self, key_id: str) -> AttestationKey:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise UnknownAttestationKey(f"unknown or retired attestation key: {key_id}") from exc


class SnapshotSigner:
    """Create canonical, bounded evidence envelopes for one observer lifetime."""

    def __init__(
        self,
        key: AttestationKey,
        *,
        ttl_s: float = 10.0,
        observer_epoch: str | None = None,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        if not math.isfinite(ttl_s) or not 0 < ttl_s <= MAX_SNAPSHOT_TTL_SECONDS:
            raise ValueError(f"ttl_s must be between 0 and {MAX_SNAPSHOT_TTL_SECONDS}")
        epoch = observer_epoch or secrets.token_hex(32)
        if re.fullmatch(LOWER_SHA256_PATTERN, epoch) is None:
            raise ValueError("observer_epoch must be 64 lowercase hexadecimal characters")
        self._key = key
        self._ttl_s = ttl_s
        self._epoch = epoch
        self._clock = clock
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(32))

    @property
    def key_id(self) -> str:
        return self._key.key_id

    @property
    def observer_epoch(self) -> str:
        return self._epoch

    def sign(
        self,
        snapshot: PerceptionSnapshot,
        *,
        issued_at: float | None = None,
    ) -> AttestedSnapshot:
        issued = self._clock() if issued_at is None else issued_at
        body = SnapshotAttestationBody(
            signature_version=SNAPSHOT_SIGNATURE_VERSION,
            key_id=self._key.key_id,
            observer_epoch=self._epoch,
            issued_at=issued,
            expires_at=issued + self._ttl_s,
            nonce=self._nonce_factory(),
            snapshot=snapshot,
        )
        signature = sign_payload(self._key.secret, body.model_dump(mode="json"))
        return AttestedSnapshot(body=body, signature=signature)


def attestation_signature_matches(key: AttestationKey, envelope: AttestedSnapshot) -> bool:
    """Check only key identity and signature; R-203 owns policy and replay checks."""
    return key.key_id == envelope.body.key_id and signature_is_valid(
        key.secret,
        envelope.body.model_dump(mode="json"),
        envelope.signature,
    )
