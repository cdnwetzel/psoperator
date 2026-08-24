"""Tests for behavior contributed by the integrated Claude/Kimi design."""

from __future__ import annotations

from PIL import Image

from psoperator.common.attestation import AttestationKey, SnapshotSigner
from psoperator.common.schema import PerceptionSnapshot, UIElementRef
from psoperator.config import load_config
from psoperator.gatekeeper import killswitch
from psoperator.gatekeeper.approval import AutoApprove
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.gatekeeper.risk import ActionContext
from psoperator.perception.a11y import A11yNode
from psoperator.perception.capture import Frame
from psoperator.perception.ocr import TextBox
from psoperator.perception.snapshot import SnapshotBuilder
from psoperator.planning.planner import RuleBasedPlanner
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.services.gatekeeper import GatekeeperService


class FakeA11y:
    def tree(self, max_nodes=None):
        return A11yNode(
            "window",
            "Editor",
            (0, 0, 100, 80),
            children=(A11yNode("button", "Save", (10, 20, 30, 20)),),
        )

    def find(self, role=None, name=None):
        return None


class FakeOCR:
    def extract(self, image, max_results=None):
        return [TextBox("Cancel", (50, 20, 35, 20), 0.95)][:max_results]

    def find(self, image, needle):
        return None


class RecordingExecutor:
    name = "recording"

    def __init__(self):
        self.actions = []

    def execute(self, action):
        self.actions.append(action)
        return "recorded"


def _frame(frame_id: int = 1) -> Frame:
    return Frame.from_image(frame_id, Image.new("RGB", (100, 80), "white"))


def _snapshot(frame: Frame, label: str = "Save") -> PerceptionSnapshot:
    element = UIElementRef(
        element_id="button-save",
        frame_id=frame.frame_id,
        label=label,
        bbox=(10, 20, 30, 20),
        control_type="button",
        source="a11y",
    )
    return PerceptionSnapshot(
        frame_id=frame.frame_id,
        captured_at=frame.captured_at,
        frame_hash=frame.sha256,
        screen_size=frame.image.size,
        elements=(element,),
    )


def _gate(tmp_path, executor=None, **overrides):
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl",
        risk_policy_path=tmp_path / "policy.json",
        kill_switch_path=tmp_path / "STOP",
        **overrides,
    )
    freshness = FreshnessTracker()
    freshness.observe(1)
    return config, Gatekeeper(
        config,
        freshness,
        approval_backend=AutoApprove(),
        executor=executor,
    )


def test_snapshot_combines_a11y_and_ocr_with_frame_binding():
    frame = _frame()
    snapshot = SnapshotBuilder(FakeA11y(), FakeOCR()).build(frame)
    assert snapshot.captured_at == frame.captured_at
    assert snapshot.frame_hash == frame.sha256
    assert snapshot.screen_size == (100, 80)
    assert {item.label for item in snapshot.elements} == {"Editor", "Save", "Cancel"}
    assert all(item.frame_id == frame.frame_id for item in snapshot.elements)


def test_rule_planner_proposes_observed_element_id():
    frame = _frame()
    snapshot = _snapshot(frame)
    action = RuleBasedPlanner().plan(snapshot, "save")
    assert action.target_element_id == "button-save"
    assert action.x is None and action.y is None


def test_gatekeeper_resolves_element_only_after_validation(tmp_path):
    executor = RecordingExecutor()
    _, gate = _gate(tmp_path, executor)
    frame = _frame()
    decision = gate.request_action(
        Action(ActionKind.CLICK, 1, target_element_id="button-save"),
        frame,
        snapshot=_snapshot(frame),
    )
    assert decision.kind is DecisionKind.EXECUTED
    assert (executor.actions[0].x, executor.actions[0].y) == (25, 30)


def test_separated_gatekeeper_accepts_only_attestation_envelope_shape(tmp_path):
    executor = RecordingExecutor()
    config = load_config(
        audit_log_path=tmp_path / "audit.jsonl",
        risk_policy_path=tmp_path / "policy.json",
        kill_switch_path=tmp_path / "STOP",
    )
    freshness = FreshnessTracker()
    service = GatekeeperService(
        Gatekeeper(config, freshness, approval_backend=AutoApprove(), executor=executor),
        freshness,
    )
    frame = _frame()
    envelope = SnapshotSigner(
        AttestationKey("observer-v1", b"s" * 32),
        observer_epoch="e" * 64,
    ).sign(_snapshot(frame), issued_at=frame.captured_at + 1)
    action = Action(ActionKind.CLICK, 1, target_element_id="button-save")

    response = service.handle(
        {
            "action": action.to_dict(),
            "attestation": envelope.model_dump(mode="json"),
            "context": {},
        }
    )
    assert response["ok"] and response["decision"]["approved"]
    assert (executor.actions[0].x, executor.actions[0].y) == (25, 30)

    raw = service.handle(
        {
            "action": action.to_dict(),
            "snapshot": envelope.snapshot.model_dump(mode="json"),
            "context": {},
        }
    )
    assert not raw["ok"] and "attestation" in raw["error"]


def test_gatekeeper_rejects_invented_element_id(tmp_path):
    _, gate = _gate(tmp_path, RecordingExecutor())
    frame = _frame()
    decision = gate.request_action(
        Action(ActionKind.CLICK, 1, target_element_id="invented"),
        frame,
        snapshot=_snapshot(frame),
    )
    assert decision.kind is DecisionKind.REJECTED_TARGET


def test_gatekeeper_rejects_out_of_bounds_coordinates(tmp_path):
    _, gate = _gate(tmp_path, RecordingExecutor())
    decision = gate.request_action(Action(ActionKind.CLICK, 1, x=100, y=79), _frame())
    assert decision.kind is DecisionKind.REJECTED_TARGET


def test_target_label_drives_risk_not_planner_prose(tmp_path):
    executor = RecordingExecutor()
    _, gate = _gate(tmp_path, executor)
    frame = _frame()
    snapshot = _snapshot(frame, label="Delete permanently")
    decision = gate.request_action(
        Action(ActionKind.CLICK, 1, target_element_id="button-save"),
        frame,
        context=ActionContext(),
        snapshot=snapshot,
    )
    assert decision.kind is DecisionKind.DENIED
    assert not executor.actions


def test_t3_can_only_execute_after_two_explicit_config_changes(tmp_path):
    executor = RecordingExecutor()
    _, gate = _gate(tmp_path, executor, hard_block_t3=False, require_approval_for_t3=True)
    frame = _frame()
    decision = gate.request_action(
        Action(ActionKind.CLICK, 1, x=1, y=1),
        frame,
        ActionContext(target_text="Delete permanently"),
    )
    assert decision.kind is DecisionKind.EXECUTED
    assert decision.approver == "human:auto"


def test_kill_switch_precedes_all_other_checks(tmp_path):
    config, gate = _gate(tmp_path, RecordingExecutor())
    killswitch.engage(config.kill_switch_path)
    decision = gate.request_action(Action(ActionKind.DONE, 1), _frame())
    assert decision.kind is DecisionKind.KILL_SWITCHED
    assert not decision.approved
