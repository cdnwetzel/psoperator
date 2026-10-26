"""R-A4 — kill-switch drills: the operator stop is exercised, not just present.

Each drill engages the stop, submits a canary that would otherwise proceed, and
requires a KILL_SWITCHED decision — proving the stop pre-empts execution, policy,
and freshness — with the decision left as a durable audit receipt. The last test
proves the drill fails loud if the stop ever stopped enforcing.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from PIL import Image

from psoperator.config import load_config
from psoperator.gatekeeper import killswitch
from psoperator.gatekeeper.drills import DrillFailed, DrillResult, kill_switch_drill
from psoperator.gatekeeper.executor import DryRunExecutor
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.perception.capture import Frame
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker


def _gk(tmp_path):
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl",
        risk_policy_path=tmp_path / "policy.json",
        kill_switch_path=tmp_path / "STOP",
    )
    freshness = FreshnessTracker()
    freshness.observe(1)
    return config, Gatekeeper(config, freshness, executor=DryRunExecutor())


def _frame():
    return Frame.from_image(1, Image.new("RGB", (40, 30), "white"))


def _audit_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_drill_preempts_a_benign_canary_and_leaves_a_receipt(tmp_path):
    config, gk = _gk(tmp_path)
    result = kill_switch_drill(
        gk,
        config.kill_switch_path,
        action=Action(ActionKind.WAIT, 1, seconds=0.0),
        frame=_frame(),
    )
    assert result == DrillResult(preempted=True, decision_kind="kill-switched")
    # the KILL_SWITCHED decision is the receipt — a durable audit row.
    kills = [r for r in _audit_rows(config.audit_log_path) if r["decision"] == "kill-switched"]
    assert len(kills) == 1


def test_drill_preempts_a_destructive_canary_over_policy(tmp_path):
    # A T3 "delete" action would be hard-blocked by policy; the stop wins first.
    config, gk = _gk(tmp_path)
    result = kill_switch_drill(
        gk,
        config.kill_switch_path,
        action=Action(ActionKind.TYPE, 1, text="delete every record now"),
        frame=_frame(),
    )
    assert result.preempted and result.decision_kind == "kill-switched"


def test_drill_preempts_a_stale_canary_over_freshness(tmp_path):
    # A frame the tracker never saw would be REJECTED_STALE; the stop wins first.
    config, gk = _gk(tmp_path)
    stale_frame = Frame.from_image(999, Image.new("RGB", (40, 30), "black"))
    result = kill_switch_drill(
        gk,
        config.kill_switch_path,
        action=Action(ActionKind.WAIT, 999, seconds=0.0),
        frame=stale_frame,
    )
    assert result.preempted and result.decision_kind == "kill-switched"


def test_drill_restores_a_previously_disengaged_switch(tmp_path):
    config, gk = _gk(tmp_path)
    assert not killswitch.is_engaged(config.kill_switch_path)
    kill_switch_drill(
        gk, config.kill_switch_path, action=Action(ActionKind.WAIT, 1, seconds=0.0), frame=_frame()
    )
    assert not killswitch.is_engaged(config.kill_switch_path)  # drill left it as it found it


def test_drill_leaves_an_already_engaged_switch_engaged(tmp_path):
    config, gk = _gk(tmp_path)
    killswitch.engage(config.kill_switch_path)
    kill_switch_drill(
        gk, config.kill_switch_path, action=Action(ActionKind.WAIT, 1, seconds=0.0), frame=_frame()
    )
    assert killswitch.is_engaged(config.kill_switch_path)  # a real stop is not lifted by a drill


def test_drill_fails_loud_if_the_stop_does_not_preempt(tmp_path):
    # A gatekeeper that ignores the kill switch must make the drill raise, not pass.
    config, _ = _gk(tmp_path)

    class _DeafGatekeeper:
        def request_action(self, action, frame, context=None, snapshot=None):
            return SimpleNamespace(kind=DecisionKind.EXECUTED)

    try:
        kill_switch_drill(
            _DeafGatekeeper(),
            config.kill_switch_path,
            action=Action(ActionKind.WAIT, 1, seconds=0.0),
            frame=_frame(),
        )
        raised = False
    except DrillFailed:
        raised = True
    assert raised, "a stop that failed to pre-empt must fail the drill, loud"
    # and the drill still restored the switch it engaged
    assert not killswitch.is_engaged(config.kill_switch_path)


def test_drill_keeps_a_stop_an_operator_engages_while_the_canary_runs(tmp_path):
    # The switch was off when the drill began, so a drill that only remembered
    # "was it engaged?" would lift the operator's stop along with its own.
    config, gk = _gk(tmp_path)

    class _OperatorStopsMidDrill:
        def request_action(self, action, frame, context=None, snapshot=None):
            killswitch.engage(config.kill_switch_path)  # the operator's real stop
            return gk.request_action(action, frame, snapshot=snapshot)

    kill_switch_drill(
        _OperatorStopsMidDrill(),
        config.kill_switch_path,
        action=Action(ActionKind.WAIT, 1, seconds=0.0),
        frame=_frame(),
    )
    assert killswitch.is_engaged(config.kill_switch_path), "the drill lifted an operator's stop"


def test_lifting_an_unowned_stop_puts_it_back(tmp_path):
    stop = tmp_path / "STOP"
    killswitch.engage(stop)
    killswitch.disengage_if_owned(stop, "PSOperator kill-switch drill someone-else.\n")
    assert killswitch.is_engaged(stop)
    assert not list(tmp_path.glob("*.claim")), "the claimed sentinel leaked"


def test_engage_exclusive_does_not_take_over_an_existing_stop(tmp_path):
    stop = tmp_path / "STOP"
    killswitch.engage(stop)
    assert killswitch.engage_exclusive(stop, "marker\n") is False
    killswitch.disengage_if_owned(stop, "marker\n")
    assert killswitch.is_engaged(stop)
