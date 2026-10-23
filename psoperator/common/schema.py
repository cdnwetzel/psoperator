"""Strict, JSON-safe schemas shared by perception, planning, and services.

These models are deliberately independent of any input-injection backend.
The planner may import this module, but it must never import
``psoperator.gatekeeper.executor``.
"""

from __future__ import annotations

import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_SNAPSHOT_ELEMENTS = 512
MAX_ELEMENT_LABEL_CHARS = 512
MAX_CONTROL_TYPE_CHARS = 128
MAX_ATTESTATION_KEY_ID_CHARS = 128
MAX_SNAPSHOT_TTL_SECONDS = 60.0
SNAPSHOT_SIGNATURE_VERSION = 1
OBSERVER_PROTOCOL_VERSION = 2

LOWER_SHA256_PATTERN = r"^[0-9a-f]{64}$"
ATTESTATION_KEY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


class UIElementRef(BaseModel):
    """A UI element observed in one exact captured frame."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    element_id: str = Field(min_length=1, max_length=128)
    frame_id: int = Field(ge=0)
    label: str = Field(default="", max_length=MAX_ELEMENT_LABEL_CHARS)
    bbox: tuple[int, int, int, int]
    control_type: str = Field(default="", max_length=MAX_CONTROL_TYPE_CHARS)
    source: Literal["a11y", "ocr", "vlm"]
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _positive_extent(self) -> "UIElementRef":
        if self.bbox[2] <= 0 or self.bbox[3] <= 0:
            raise ValueError("bbox width and height must be positive")
        return self

    @property
    def center(self) -> tuple[int, int]:
        x, y, width, height = self.bbox
        return x + width // 2, y + height // 2


class PerceptionSnapshot(BaseModel):
    """Element inventory bound to a frame id and content hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    frame_id: int = Field(ge=0)
    captured_at: float = Field(ge=0)
    frame_hash: str = Field(pattern=LOWER_SHA256_PATTERN)
    screen_size: tuple[int, int]
    elements: tuple[UIElementRef, ...] = Field(default=(), max_length=MAX_SNAPSHOT_ELEMENTS)

    @model_validator(mode="after")
    def _elements_match_frame(self) -> "PerceptionSnapshot":
        if not math.isfinite(self.captured_at):
            raise ValueError("captured_at must be finite")
        if self.screen_size[0] <= 0 or self.screen_size[1] <= 0:
            raise ValueError("screen width and height must be positive")
        if any(element.frame_id != self.frame_id for element in self.elements):
            raise ValueError("every element must belong to the snapshot frame")
        ids = [element.element_id for element in self.elements]
        if len(ids) != len(set(ids)):
            raise ValueError("element ids must be unique within a snapshot")
        return self

    def find(self, element_id: str) -> UIElementRef | None:
        return next((item for item in self.elements if item.element_id == element_id), None)


class SnapshotAttestationBody(BaseModel):
    """Canonical signed evidence emitted by one observer service lifetime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signature_version: Literal[1]
    key_id: str = Field(
        min_length=1,
        max_length=MAX_ATTESTATION_KEY_ID_CHARS,
        pattern=ATTESTATION_KEY_ID_PATTERN,
    )
    observer_epoch: str = Field(pattern=LOWER_SHA256_PATTERN)
    issued_at: float = Field(ge=0)
    expires_at: float = Field(gt=0)
    nonce: str = Field(pattern=LOWER_SHA256_PATTERN)
    snapshot: PerceptionSnapshot

    @model_validator(mode="after")
    def _valid_lifetime(self) -> "SnapshotAttestationBody":
        if not math.isfinite(self.issued_at) or not math.isfinite(self.expires_at):
            raise ValueError("attestation times must be finite")
        if self.issued_at < self.snapshot.captured_at:
            raise ValueError("attestation cannot predate its captured snapshot")
        lifetime = self.expires_at - self.issued_at
        if not 0 < lifetime <= MAX_SNAPSHOT_TTL_SECONDS:
            raise ValueError(
                f"attestation lifetime must be between 0 and {MAX_SNAPSHOT_TTL_SECONDS} seconds"
            )
        return self


class AttestedSnapshot(BaseModel):
    """Strict envelope carrying signed observer evidence through the planner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    body: SnapshotAttestationBody
    signature: str = Field(pattern=LOWER_SHA256_PATTERN)

    @property
    def snapshot(self) -> PerceptionSnapshot:
        return self.body.snapshot


class ObserverRequest(BaseModel):
    """Strict request schema for the independent observer service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[2]
    op: Literal["observe", "health"]


class ObserverHealth(BaseModel):
    """Bounded lifecycle state returned by the observer service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ready", "degraded", "stopped"]
    backend: str = Field(min_length=1, max_length=128)
    started_at: float = Field(ge=0)
    last_success_at: float | None = Field(default=None, ge=0)
    last_sequence: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    error: str = Field(default="", max_length=512)
    attestation_key_id: str = Field(
        min_length=1,
        max_length=MAX_ATTESTATION_KEY_ID_CHARS,
        pattern=ATTESTATION_KEY_ID_PATTERN,
    )
    observer_epoch: str = Field(pattern=LOWER_SHA256_PATTERN)
