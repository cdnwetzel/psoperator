"""Frame-id binding — the freshness invariant.

Every model decision is grounded in exactly one observed frame. The action
the model returns must echo that frame's id. If the screen has moved on
(a newer frame exists) the action is STALE and must not execute — clicking
coordinates computed against an old screen is how agents click the wrong
button. Fail closed: any doubt means reject.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from psoperator.runtime.actions import Action


class Freshness(str, Enum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"  # e.g. repaired call-syntax action; treated as stale by the gatekeeper


@dataclass(frozen=True)
class FreshnessVerdict:
    status: Freshness
    action_frame_id: int
    latest_frame_id: int | None

    @property
    def ok(self) -> bool:
        return self.status is Freshness.FRESH


class FreshnessTracker:
    """Tracks the newest frame id the runtime has observed."""

    def __init__(self) -> None:
        self._latest: int | None = None

    def observe(self, frame_id: int) -> None:
        if self._latest is None or frame_id > self._latest:
            self._latest = frame_id

    @property
    def latest(self) -> int | None:
        return self._latest

    def check(self, action: Action) -> FreshnessVerdict:
        """Fail closed: unknown latest, or mismatched id → not FRESH."""
        if self._latest is None:
            return FreshnessVerdict(Freshness.UNKNOWN, action.frame_id, None)
        if action.frame_id < 0:
            return FreshnessVerdict(Freshness.UNKNOWN, action.frame_id, self._latest)
        if action.frame_id == self._latest:
            return FreshnessVerdict(Freshness.FRESH, action.frame_id, self._latest)
        return FreshnessVerdict(Freshness.STALE, action.frame_id, self._latest)
