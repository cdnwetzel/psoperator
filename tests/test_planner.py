"""LocalElementPlanner guards: it never calls the model on an empty snapshot,
and it refuses answers that are not bound to an element of the snapshot."""

from __future__ import annotations

import json

import httpx
import pytest

from psoperator.common.schema import PerceptionSnapshot, UIElementRef
from psoperator.planning.planner import LocalElementPlanner
from psoperator.runtime.actions import ActionKind


def _snapshot(*elements):
    return PerceptionSnapshot(
        frame_id=3,
        captured_at=1.0,
        frame_hash="0" * 64,
        screen_size=(100, 80),
        elements=elements,
    )


SAVE = UIElementRef(
    element_id="a11y-1",
    frame_id=3,
    label="Save",
    bbox=(10, 20, 30, 20),
    control_type="button",
    source="a11y",
)


def _planner(answer: dict | None):
    calls = []

    def handler(request):
        calls.append(request)
        content = json.dumps(answer)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    planner = LocalElementPlanner("http://planner.invalid/v1", "m")
    planner._client.close()
    planner._client = httpx.Client(
        base_url="http://planner.invalid/v1", transport=httpx.MockTransport(handler)
    )
    return planner, calls


def test_empty_snapshot_fails_without_calling_the_model():
    planner, calls = _planner({"action": "click", "x": 1, "y": 1, "frame_id": 3})
    action = planner.plan(_snapshot(), "convert")
    assert action.kind is ActionKind.FAIL
    assert action.frame_id == 3
    assert "no elements" in action.reason
    assert calls == []


@pytest.mark.parametrize(
    "answer",
    [
        {"action": "click", "x": 25, "y": 30, "frame_id": 3},
        {"action": "double_click", "x": 25, "y": 30, "frame_id": 3},
        {"action": "type", "text": "212", "frame_id": 3},
        {"action": "key", "keys": ["enter"], "frame_id": 3},
    ],
)
def test_unbound_input_answer_is_refused(answer):
    planner, calls = _planner(answer)
    with pytest.raises(ValueError, match="not bound to an element"):
        planner.plan(_snapshot(SAVE), "save")
    assert len(calls) == 1


@pytest.mark.parametrize(
    "answer",
    [
        {"action": "scroll", "target_element_id": "a11y-1", "amount": -3, "frame_id": 3},
        {"action": "drag", "x": 1, "y": 1, "to_x": 5, "to_y": 5, "frame_id": 3},
    ],
)
def test_unsupported_kind_is_refused(answer):
    planner, _ = _planner(answer)
    with pytest.raises(ValueError, match="not supported"):
        planner.plan(_snapshot(SAVE), "save")


def test_invented_id_is_still_refused():
    planner, _ = _planner({"action": "click", "target_element_id": "nope", "frame_id": 3})
    with pytest.raises(ValueError, match="absent from the snapshot"):
        planner.plan(_snapshot(SAVE), "save")


@pytest.mark.parametrize(
    ("answer", "kind"),
    [
        ({"action": "click", "target_element_id": "a11y-1", "frame_id": 3}, ActionKind.CLICK),
        (
            {"action": "type", "target_element_id": "a11y-1", "text": "x", "frame_id": 3},
            ActionKind.TYPE,
        ),
        ({"action": "wait", "seconds": 1, "frame_id": 3}, ActionKind.WAIT),
        ({"action": "done", "frame_id": 3}, ActionKind.DONE),
        ({"action": "fail", "reason": "stuck", "frame_id": 3}, ActionKind.FAIL),
    ],
)
def test_bound_and_terminal_answers_pass(answer, kind):
    # Positive control for the guards above.
    planner, _ = _planner(answer)
    assert planner.plan(_snapshot(SAVE), "save").kind is kind
