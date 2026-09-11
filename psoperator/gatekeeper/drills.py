"""Kill-switch drills (A4).

The kill switch is only trustworthy if it is exercised, not just present. A drill
engages the operator stop, submits a canary action that would *otherwise* proceed,
and asserts the gatekeeper returns ``KILL_SWITCHED`` — proving the stop pre-empts
freshness, policy, and execution (it is checked before all of them). The
``KILL_SWITCHED`` decision is written to the same hash-chained audit as every other
decision, so the drill leaves a durable receipt. The drill restores the prior
switch state, and fails loud if the stop did not pre-empt.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from psoperator.gatekeeper import killswitch
from psoperator.gatekeeper.gatekeeper import DecisionKind


class DrillFailed(Exception):
    """A drill's invariant did not hold — e.g. the kill switch failed to
    pre-empt a canary. Never swallowed: a failed safety drill is stop-the-line."""


@dataclass(frozen=True)
class DrillResult:
    preempted: bool
    decision_kind: str


def kill_switch_drill(
    gatekeeper, kill_switch_path: Path, *, action, frame, snapshot=None
) -> DrillResult:
    """Run one kill-switch drill against a live gatekeeper.

    Engages the switch, submits the canary, and requires the decision to be
    ``KILL_SWITCHED`` — which is audited as the drill receipt. Restores the switch
    to its prior state whether or not the canary pre-empted, then raises
    :class:`DrillFailed` if it did not. ``snapshot`` is irrelevant to the outcome
    (the stop is checked before perception), but is passed through for realism.
    """
    was_engaged = killswitch.is_engaged(kill_switch_path)
    killswitch.engage(kill_switch_path)
    try:
        decision = gatekeeper.request_action(action, frame, snapshot=snapshot)
    finally:
        if not was_engaged:
            killswitch.disengage(kill_switch_path)

    if decision.kind is not DecisionKind.KILL_SWITCHED:
        raise DrillFailed(
            f"kill switch did not pre-empt the canary action: got {decision.kind.value}, "
            "expected kill-switched. The stop is not enforced — stop the line."
        )
    return DrillResult(preempted=True, decision_kind=decision.kind.value)
