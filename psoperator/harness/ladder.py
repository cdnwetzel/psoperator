"""The escalation ladder: what to do when a gate fails.

This is the codification of the choices a human (or Claude) made by hand while
driving pxx today. Each failure gets a deterministic response, escalating only
when the cheaper response did not move the gate. The rungs, in order:

  RETRY    re-run the same lane once — small local models often fumble the
           edit tool's exact-match string, blame the environment, and land on
           the second try (pxx tutorial troubleshooting #3).
  SPLIT    turn a multi-violation gate into one sub-task per violation — the
           whack-a-mole fix. Requires a collect-all gate; if only one
           violation is reported there is nothing to split, so we don't.
  ESCALATE move up one model lane — proven boundary today: a 14B lands
           2-line edits but fumbles whole functions; a 20B handled them.
  JUDGE    ask the vision judge whether the screen actually matches intent —
           for GUI work where the text gate passed but pixels may not (or to
           explain a stubborn on-screen failure).
  REVIEW   bundle evidence and hand to a human. The top rung, never skipped:
           the harness stops rather than thrash.

Progress detection matters: if a round changed nothing and the violation set is
identical to last round, retrying is pointless — jump straight past RETRY.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from psoperator.harness.model import GateResult, Lane, next_lane


class Rung(str, Enum):
    RETRY = "retry"
    SPLIT = "split"
    ESCALATE = "escalate"
    JUDGE = "judge"
    REVIEW = "review"


@dataclass(frozen=True)
class Decision:
    rung: Rung
    lane: Lane  # the lane to use next (unchanged unless rung is ESCALATE)
    reason: str


@dataclass(frozen=True)
class Attempt:
    """One (coder round + gate) observation the ladder reasons over."""

    lane: Lane
    changed: bool
    gate: GateResult


class EscalationLadder:
    """Pure decision function over the attempt history for one task.

    Deterministic and side-effect free: given what has been tried, it returns
    the next rung. ``vision_enabled`` gates the JUDGE rung (skip it with no
    judge configured). ``allow_split`` lets a caller disable splitting for a
    task that is already a single atomic sub-task.
    """

    def __init__(self, *, vision_enabled: bool = False, allow_split: bool = True) -> None:
        self._vision_enabled = vision_enabled
        self._allow_split = allow_split

    def decide(self, history: tuple[Attempt, ...], *, judged: bool = False) -> Decision:
        """Next rung given the attempt history.

        ``judged`` is the caller's record of whether the vision judge has
        already been consulted for this task (the SoftLoop owns that state, so
        the ladder stays a pure function). Once judged, JUDGE is never returned
        again — the loop escalates to human REVIEW instead of re-asking blind.
        """
        if not history:
            raise ValueError("decide() needs at least one attempt")
        last = history[-1]
        if last.gate.passed:
            raise ValueError("decide() is only called after a failing gate")

        lane = last.lane
        splittable = self._allow_split and len(last.gate.violations) > 1
        can_judge = self._vision_enabled and not judged

        # No semantic progress across two rounds (identical failing set, nothing
        # changed) — retrying the same lane is proven futile. Skip to a
        # structural move: split if we can, else escalate, else review.
        if _stalled(history):
            if splittable:
                return Decision(Rung.SPLIT, lane, "stalled; splitting collected violations")
            up = next_lane(lane)
            if up is not None:
                return Decision(Rung.ESCALATE, up, f"stalled at {lane.value}; escalating lane")
            if can_judge:
                return Decision(Rung.JUDGE, lane, "stalled at top lane; consulting vision judge")
            return Decision(Rung.REVIEW, lane, "stalled at top lane with no cheaper move")

        attempts_this_lane = sum(1 for a in history if a.lane == lane)

        # First failure on this lane: a single cheap retry (transient fumble).
        if attempts_this_lane == 1:
            return Decision(Rung.RETRY, lane, "first failure on this lane; one retry")

        # Retried and still failing with multiple violations: split them.
        if splittable:
            return Decision(Rung.SPLIT, lane, "persistent multi-violation failure; splitting")

        # Single stubborn violation: escalate the lane if we can.
        up = next_lane(lane)
        if up is not None:
            return Decision(Rung.ESCALATE, up, f"persistent failure at {lane.value}; escalating")

        # Top lane, single violation, still failing: try the eyes once, then human.
        if can_judge:
            return Decision(Rung.JUDGE, lane, "top lane exhausted; consulting vision judge")
        return Decision(Rung.REVIEW, lane, "top lane exhausted; escalating to human review")


def _stalled(history: tuple[Attempt, ...]) -> bool:
    """True when the last two attempts, ON THE SAME LANE, made no change and hit
    the same violations. The same-lane guard matters: right after an ESCALATE the
    first attempt on the new lane can be unchanged with the old lane's violation
    set — that is a fresh lane's first try, not a stall, and must still get its
    retry (else a DEEP-lane run ends at REVIEW one attempt early)."""
    if len(history) < 2:
        return False
    a, b = history[-2], history[-1]
    return (
        a.lane == b.lane
        and not a.changed
        and not b.changed
        and a.gate.violations == b.gate.violations
        and bool(b.gate.violations)
    )
