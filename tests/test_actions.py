"""Action parser round-trip + failure modes."""

from __future__ import annotations

import pytest

from psoperator.runtime.actions import (
    Action,
    ActionKind,
    ActionParseError,
    parse_action,
)

CASES = [
    Action(ActionKind.CLICK, frame_id=3, x=100, y=200),
    Action(ActionKind.RIGHT_CLICK, frame_id=3, x=1, y=2),
    Action(ActionKind.DOUBLE_CLICK, frame_id=3, x=5, y=6),
    Action(ActionKind.TYPE, frame_id=4, text="hello world"),
    Action(ActionKind.KEY, frame_id=5, keys=("ctrl", "s")),
    Action(ActionKind.SCROLL, frame_id=6, x=50, y=50, amount=-3),
    Action(ActionKind.DRAG, frame_id=7, x=10, y=20, to_x=300, to_y=400),
    Action(ActionKind.WAIT, frame_id=8, seconds=1.5),
    Action(ActionKind.DONE, frame_id=9),
    Action(ActionKind.FAIL, frame_id=10, reason="cannot find submit"),
]


class TestRoundTrip:
    @pytest.mark.parametrize("action", CASES, ids=[a.kind.value for a in CASES])
    def test_serialize_then_parse_is_identity(self, action: Action):
        assert parse_action(action.to_text()) == action

    def test_prose_wrapping_is_tolerated(self):
        raw = 'Sure! I will click there. {"action":"click","x":1,"y":2,"frame_id":3} Done.'
        a = parse_action(raw)
        assert (a.kind, a.x, a.y, a.frame_id) == (ActionKind.CLICK, 1, 2, 3)

    def test_call_syntax_with_repair_frame_id(self):
        a = parse_action("click(120, 240)", current_frame_id=7)
        assert (a.kind, a.x, a.y, a.frame_id) == (ActionKind.CLICK, 120, 240, 7)

    def test_type_call_syntax(self):
        a = parse_action("type('hello there')", current_frame_id=1)
        assert a.kind is ActionKind.TYPE and a.text == "hello there"


class TestFailureModes:
    def test_garbage_raises(self):
        with pytest.raises(ActionParseError):
            parse_action("I think we should maybe click something?")

    def test_missing_frame_id_raises(self):
        with pytest.raises(ActionParseError):
            parse_action('{"action":"click","x":1,"y":2}')

    def test_missing_required_field_raises(self):
        with pytest.raises(ActionParseError):
            parse_action('{"action":"click","x":1,"frame_id":2}')  # no y
        with pytest.raises(ActionParseError):
            parse_action('{"action":"type","frame_id":2}')  # no text

    def test_unknown_action_raises(self):
        with pytest.raises(ActionParseError):
            parse_action('{"action":"teleport","frame_id":1}')

    def test_call_syntax_without_frame_id_fails_closed(self):
        with pytest.raises(ActionParseError):
            parse_action("click(1, 2)")  # no current_frame_id supplied

    def test_to_dict_omits_defaults(self):
        d = Action(ActionKind.CLICK, frame_id=1, x=1, y=1).to_dict()
        assert d == {"action": "click", "frame_id": 1, "x": 1, "y": 1}
