"""Kill-switch drills (A4).

The kill switch is only trustworthy if it is exercised, not just present. A drill
engages the operator stop, submits a canary action that would *otherwise* proceed,
and asserts the gatekeeper returns ``KILL_SWITCHED`` — proving the stop pre-empts
freshness, policy, and execution (it is checked before all of them). The
``KILL_SWITCHED`` decision is written to the same hash-chained audit as every other
decision, so the drill leaves a durable receipt. The drill lifts only the stop it
created itself, and fails loud if the stop did not pre-empt.
"""

from __future__ import annotations

import secrets
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
    ``KILL_SWITCHED`` — which is audited as the drill receipt. Lifts the stop it
    engaged (never an operator's) whether or not the canary pre-empted, then raises
    :class:`DrillFailed` if it did not. ``snapshot`` is irrelevant to the outcome
    (the stop is checked before perception), but is passed through for realism.
    """
    # The drill lifts only the stop it created. A stop that already existed, or
    # one an operator engages while the canary runs, is not the drill's to lift.
    marker = f"PSOperator kill-switch drill {secrets.token_hex(16)}.\n"
    owned = killswitch.engage_exclusive(kill_switch_path, marker)
    try:
        decision = gatekeeper.request_action(action, frame, snapshot=snapshot)
    finally:
        if owned:
            killswitch.disengage_if_owned(kill_switch_path, marker)

    if decision.kind is not DecisionKind.KILL_SWITCHED:
        raise DrillFailed(
            f"kill switch did not pre-empt the canary action: got {decision.kind.value}, "
            "expected kill-switched. The stop is not enforced — stop the line."
        )
    return DrillResult(preempted=True, decision_kind=decision.kind.value)
