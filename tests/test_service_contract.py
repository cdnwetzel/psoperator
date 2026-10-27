"""The gatekeeper service admits only element-bound input of supported kinds.

A planner client may be compromised, so the R-306 contract is enforced at the
service, not in a prompt: `scroll` and `drag` are refused, every input action
must name an element of the attested snapshot, and keyboard input must target
an accessibility element (an OCR text box is not a focusable control). Each
refusal is an audited decision, and nothing reaches the executor. The
in-process gatekeeper keeps its looser rules.
"""

from __future__ import annotations

import json

import pytest
from PIL import Image

from psoperator.common.attestation import AttestationKey, AttestationKeyring, SnapshotSigner
from psoperator.common.schema import PerceptionSnapshot, UIElementRef
from psoperator.config import load_config
from psoperator.gatekeeper.approval import AutoApprove
from psoperator.gatekeeper.attestation_gate import AttestationGate
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.perception.capture import Frame
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.services.gatekeeper import GatekeeperService

EPOCH = "e" * 64


class RecordingExecutor:
    name = "recording"

    def __init__(self):
        self.actions = []

    def execute(self, action):
        self.actions.append(action)
        return "recorded"


def _element(element_id, source, control_type):
    return UIElementRef(
        element_id=element_id,
        frame_id=1,
        label="Value",
        bbox=(10, 20, 30, 20),
        control_type=control_type,
        source=source,
    )


def _setup(tmp_path):
    frame = Frame.from_image(1, Image.new("RGB", (100, 80), "white"))
    snapshot = PerceptionSnapshot(
        frame_id=1,
        captured_at=frame.captured_at,
        frame_hash=frame.sha256,
        screen_size=frame.image.size,
        elements=(_element("a11y-1", "a11y", "text"), _element("ocr-1", "ocr", "text")),
    )
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl",
        risk_policy_path=tmp_path / "policy.json",
        kill_switch_path=tmp_path / "STOP",
    )
    executor = RecordingExecutor()
    freshness = FreshnessTracker()
    gatekeeper = Gatekeeper(config, freshness, approval_backend=AutoApprove(), executor=executor)
    key = AttestationKey("observer-v1", b"s" * 32)
    gate = AttestationGate(
        AttestationKeyring([key]), expected_epoch=EPOCH, clock=lambda: frame.captured_at + 2
    )
    envelope = SnapshotSigner(key, observer_epoch=EPOCH).sign(
        snapshot, issued_at=frame.captured_at + 1
    )
    service = GatekeeperService(gatekeeper, freshness, gate)
    return service, envelope, executor, gatekeeper, frame, snapshot, config


def _submit(service, envelope, action):
    return service.handle(
        {
            "action": action.to_dict(),
            "attestation": envelope.model_dump(mode="json"),
            "context": {},
        }
    )


def _audited_decisions(config):
    lines = config.audit_log_path.read_text().splitlines()
    return [json.loads(line).get("decision") for line in lines]


REFUSED = [
    # scroll and drag are not part of the R-306 action subset
    (Action(ActionKind.SCROLL, 1, x=5, y=5, amount=-3), DecisionKind.DENIED, "not allowed"),
    (Action(ActionKind.DRAG, 1, x=5, y=5, to_x=50, to_y=50), DecisionKind.DENIED, "not allowed"),
    (
        Action(ActionKind.SCROLL, 1, target_element_id="a11y-1", amount=-3),
        DecisionKind.DENIED,
        "not allowed",
    ),
    # unbound input: coordinate-only clicks, bare type and key
    (Action(ActionKind.CLICK, 1, x=25, y=30), DecisionKind.REJECTED_TARGET, "must name"),
    (Action(ActionKind.DOUBLE_CLICK, 1, x=25, y=30), DecisionKind.REJECTED_TARGET, "must name"),
    (
        Action(ActionKind.RIGHT_CLICK, 1, x=25, y=30, button="right"),
        DecisionKind.REJECTED_TARGET,
        "must name",
    ),
    (Action(ActionKind.TYPE, 1, text="212"), DecisionKind.REJECTED_TARGET, "must name"),
    (Action(ActionKind.KEY, 1, keys=("enter",)), DecisionKind.REJECTED_TARGET, "must name"),
    # an id the snapshot does not hold
    (
        Action(ActionKind.TYPE, 1, target_element_id="invented", text="212"),
        DecisionKind.REJECTED_TARGET,
        "absent",
    ),
    # keyboard input into an OCR box, which cannot take focus
    (
        Action(ActionKind.TYPE, 1, target_element_id="ocr-1", text="212"),
        DecisionKind.REJECTED_TARGET,
        "accessibility",
    ),
    (
        Action(ActionKind.KEY, 1, target_element_id="ocr-1", keys=("enter",)),
        DecisionKind.REJECTED_TARGET,
        "accessibility",
    ),
]


@pytest.mark.parametrize(("action", "kind", "reason"), REFUSED)
def test_service_refuses_outside_the_contract(tmp_path, action, kind, reason):
    service, envelope, executor, _, _, _, config = _setup(tmp_path)
    response = _submit(service, envelope, action)
    assert response["ok"]
    decision = response["decision"]
    assert decision["kind"] == kind.value
    assert reason in decision["reason"]
    assert not decision["approved"]
    assert not executor.actions
    assert _audited_decisions(config) == [kind.value]  # the refusal is audited


ADMITTED = [
    Action(ActionKind.CLICK, 1, target_element_id="a11y-1"),
    Action(ActionKind.CLICK, 1, target_element_id="ocr-1"),  # a click may target OCR text
    Action(ActionKind.DOUBLE_CLICK, 1, target_element_id="a11y-1"),
    Action(ActionKind.TYPE, 1, target_element_id="a11y-1", text="212"),
    Action(ActionKind.KEY, 1, target_element_id="a11y-1", keys=("enter",)),
    Action(ActionKind.WAIT, 1, seconds=0.5),
]


@pytest.mark.parametrize("action", ADMITTED)
def test_service_admits_bound_input_and_wait(tmp_path, action):
    # Positive control: the contract does not refuse what R-306 supports.
    service, envelope, executor, _, _, _, _ = _setup(tmp_path)
    response = _submit(service, envelope, action)
    assert response["decision"]["kind"] == DecisionKind.EXECUTED.value
    assert len(executor.actions) == 1


@pytest.mark.parametrize("kind", [ActionKind.DONE, ActionKind.FAIL])
def test_service_admits_terminal_actions(tmp_path, kind):
    service, envelope, executor, _, _, _, _ = _setup(tmp_path)
    response = _submit(service, envelope, Action(kind, 1))
    assert response["decision"]["kind"] in (DecisionKind.DONE.value, DecisionKind.FAILED.value)
    assert not executor.actions


def test_in_process_gatekeeper_keeps_its_looser_rules(tmp_path):
    # The contract is the service's; a direct call is unchanged.
    _, _, executor, gatekeeper, frame, snapshot, _ = _setup(tmp_path)
    gatekeeper._freshness.observe(1)
    decision = gatekeeper.request_action(
        Action(ActionKind.TYPE, 1, text="212"), frame, snapshot=snapshot
    )
    assert decision.kind is DecisionKind.EXECUTED
    assert len(executor.actions) == 1


def _submit_raw(service, envelope, raw_action):
    return service.handle(
        {"action": raw_action, "attestation": envelope.model_dump(mode="json"), "context": {}}
    )


def test_bound_click_lands_on_the_element_not_the_supplied_coordinates(tmp_path):
    service, envelope, executor, _, _, _, _ = _setup(tmp_path)
    response = _submit(
        service, envelope, Action(ActionKind.CLICK, 1, target_element_id="a11y-1", x=99, y=79)
    )
    assert response["decision"]["kind"] == DecisionKind.EXECUTED.value
    assert (executor.actions[0].x, executor.actions[0].y) == (25, 30)  # bbox centre


@pytest.mark.parametrize(
    "raw_action",
    [
        {"action": "SCROLL", "x": 5, "y": 5, "amount": -3, "frame_id": 1},
        {"action": "Click", "x": 25, "y": 30, "frame_id": 1},
        {"action": "click", "x": 25, "y": 30, "button": "right", "frame_id": 1},
    ],
)
def test_kind_spelling_and_button_do_not_bypass_the_contract(tmp_path, raw_action):
    service, envelope, executor, _, _, _, _ = _setup(tmp_path)
    response = _submit_raw(service, envelope, raw_action)
    assert response["ok"] and not response["decision"]["approved"]
    assert not executor.actions


def test_call_syntax_is_held_to_the_same_contract(tmp_path):
    # Call syntax carries no frame_id, and the service never supplies one, so
    # `click(25, 30)` is an invalid request before any decision is made.
    service, envelope, executor, _, _, _, config = _setup(tmp_path)
    response = _submit_raw(service, envelope, "click(25, 30)")
    assert not response["ok"] and "invalid request" in response["error"]
    assert not executor.actions


@pytest.mark.parametrize(
    ("raw_action", "kind", "executed"),
    [
        (
            {"action": "wait", "seconds": 0.5, "x": 25, "y": 30, "frame_id": 1},
            DecisionKind.EXECUTED,
            [ActionKind.WAIT],
        ),
        (
            {"action": "done", "x": 25, "y": 30, "text": "212", "frame_id": 1},
            DecisionKind.DONE,
            [],
        ),
    ],
)
def test_extra_fields_on_wait_and_done_send_no_input(tmp_path, raw_action, kind, executed):
    service, envelope, executor, _, _, _, _ = _setup(tmp_path)
    response = _submit_raw(service, envelope, raw_action)
    assert response["ok"] and response["decision"]["kind"] == kind.value
    assert [a.kind for a in executor.actions] == executed


def test_kill_switch_is_reported_before_the_contract(tmp_path):
    from psoperator.gatekeeper import killswitch

    service, envelope, executor, _, _, _, config = _setup(tmp_path)
    killswitch.engage(config.kill_switch_path)
    response = _submit(service, envelope, Action(ActionKind.SCROLL, 1, x=5, y=5, amount=-3))
    assert response["decision"]["kind"] == DecisionKind.KILL_SWITCHED.value
    assert not executor.actions


def test_staleness_is_reported_before_the_contract(tmp_path):
    service, envelope, executor, _, _, _, _ = _setup(tmp_path)
    response = _submit(service, envelope, Action(ActionKind.SCROLL, 0, x=5, y=5, amount=-3))
    assert response["decision"]["kind"] == DecisionKind.REJECTED_STALE.value
    assert not executor.actions
