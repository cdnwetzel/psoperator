"""OSWorld-style action space + parser.

The model is asked to emit exactly one action per turn, in JSON:

    {"action": "click", "x": 412, "y": 305, "frame_id": 7}
    {"action": "type", "text": "hello", "frame_id": 7}
    {"action": "key", "keys": ["ctrl", "s"], "frame_id": 7}
    {"action": "scroll", "x": 500, "y": 400, "amount": -3, "frame_id": 7}
    {"action": "drag", "x": 10, "y": 20, "to_x": 300, "to_y": 400, "frame_id": 7}
    {"action": "wait", "seconds": 1.5, "frame_id": 7}
    {"action": "done", "frame_id": 7}
    {"action": "fail", "reason": "cannot find the submit button", "frame_id": 7}

A compact ``click(412, 305)`` call-syntax is also accepted (some local GUI
models are trained on it). ``parse_action`` tolerates surrounding prose by
scanning for the first JSON object / call expression.

`frame_id` is mandatory: it binds the action to the exact frame the model
saw, and the gatekeeper rejects stale echoes (runtime/freshness.py).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum


class ActionKind(str, Enum):
    CLICK = "click"
    RIGHT_CLICK = "right_click"
    DOUBLE_CLICK = "double_click"
    TYPE = "type"
    KEY = "key"
    SCROLL = "scroll"
    DRAG = "drag"
    WAIT = "wait"
    DONE = "done"
    FAIL = "fail"


class ActionParseError(ValueError):
    pass


@dataclass(frozen=True)
class Action:
    kind: ActionKind
    frame_id: int
    target_element_id: str | None = None
    x: int | None = None
    y: int | None = None
    to_x: int | None = None
    to_y: int | None = None
    text: str | None = None
    keys: tuple[str, ...] = field(default_factory=tuple)
    amount: int | None = None  # scroll clicks; negative = down
    seconds: float | None = None  # wait
    button: str = "left"
    reason: str | None = None  # fail

    def __post_init__(self) -> None:
        _validate(self)

    def to_dict(self) -> dict:
        d: dict = {"action": self.kind.value, "frame_id": self.frame_id}
        for k in (
            "target_element_id",
            "x",
            "y",
            "to_x",
            "to_y",
            "text",
            "amount",
            "seconds",
            "reason",
        ):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.keys:
            d["keys"] = list(self.keys)
        if self.button != "left":
            d["button"] = self.button
        return d

    def to_text(self) -> str:
        """Canonical wire form (what we ask the model to emit)."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


_CALL_RE = re.compile(r"(\w+)\s*\(([^)]*)\)")
_ALLOWED_FIELDS = {
    "action",
    "frame_id",
    "target_element_id",
    "x",
    "y",
    "to_x",
    "to_y",
    "text",
    "keys",
    "amount",
    "seconds",
    "button",
    "reason",
}


def _from_mapping(m: dict) -> Action:
    unexpected = set(m) - _ALLOWED_FIELDS
    if unexpected:
        raise ActionParseError(f"unexpected action fields: {sorted(unexpected)}")
    try:
        kind = ActionKind(str(m["action"]).lower())
        frame_id = int(m["frame_id"])
    except (KeyError, ValueError) as e:
        raise ActionParseError(f"missing/invalid action or frame_id: {e}") from e

    keys = m.get("keys") or ()
    if isinstance(keys, str):
        keys = (keys,)
    kwargs = {
        "target_element_id": m.get("target_element_id"),
        "x": m.get("x"),
        "y": m.get("y"),
        "to_x": m.get("to_x"),
        "to_y": m.get("to_y"),
        "text": m.get("text"),
        "amount": m.get("amount"),
        "seconds": m.get("seconds"),
        "button": m.get("button", "left"),
        "reason": m.get("reason"),
        "keys": tuple(str(k).lower() for k in keys),
    }
    return Action(kind=kind, frame_id=frame_id, **kwargs)


def _validate(a: Action) -> None:
    if not isinstance(a.frame_id, int):
        raise ActionParseError("frame_id must be an integer")
    if a.target_element_id is not None and not (1 <= len(a.target_element_id) <= 128):
        raise ActionParseError("target_element_id must contain 1..128 characters")
    if len(a.keys) > 4:
        raise ActionParseError("hotkey cannot contain more than four keys")
    if a.text is not None and len(a.text) > 10_000:
        raise ActionParseError("typed text exceeds the 10,000 character limit")
    for name in ("x", "y", "to_x", "to_y", "amount"):
        value = getattr(a, name)
        if value is not None and not isinstance(value, int):
            raise ActionParseError(f"{name} must be an integer")
    if a.kind in (ActionKind.CLICK, ActionKind.RIGHT_CLICK, ActionKind.DOUBLE_CLICK):
        has_coordinates = a.x is not None and a.y is not None
        if not has_coordinates and not a.target_element_id:
            raise ActionParseError(
                f"action {a.kind.value!r} requires coordinates or target_element_id"
            )

    need = {
        ActionKind.TYPE: ("text",),
        ActionKind.KEY: ("keys",),
        ActionKind.SCROLL: ("amount",),
        ActionKind.DRAG: ("x", "y", "to_x", "to_y"),
        ActionKind.WAIT: ("seconds",),
    }.get(a.kind, ())
    for f in need:
        if getattr(a, f) in (None, (), ""):
            raise ActionParseError(f"action {a.kind.value!r} requires {f!r}")


def _from_call(name: str, argstr: str) -> Action:
    try:
        kind = ActionKind(name.lower())
    except ValueError as e:
        raise ActionParseError(f"unknown call {name!r}") from e
    args = [a.strip().strip("'\"") for a in argstr.split(",") if a.strip()]
    nums = []
    for a in args:
        try:
            nums.append(int(a))
        except ValueError:
            nums.append(None)
    # call-syntax cannot carry frame_id; caller must attach it
    if (
        kind in (ActionKind.CLICK, ActionKind.RIGHT_CLICK, ActionKind.DOUBLE_CLICK)
        and len(nums) >= 2
    ):
        return Action(kind=kind, frame_id=-1, x=nums[0], y=nums[1])
    if kind is ActionKind.TYPE and args:
        return Action(kind=kind, frame_id=-1, text=",".join(args))
    if kind is ActionKind.KEY and args:
        return Action(kind=kind, frame_id=-1, keys=tuple(a.lower() for a in args))
    raise ActionParseError(f"cannot map call {name}({argstr}) to an action")


def parse_action(text: str, current_frame_id: int | None = None) -> Action:
    """Parse model output into an Action.

    ``current_frame_id`` is used only to repair call-syntax output, which
    cannot carry a frame id. JSON output must echo the id itself; a missing
    or non-integer frame_id is a parse error (fail closed).
    """
    decoder = json.JSONDecoder()
    for start, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[start:])
            if isinstance(value, dict):
                return _from_mapping(value)
        except (json.JSONDecodeError, ActionParseError):
            continue
    m = _CALL_RE.search(text)
    if m:
        a = _from_call(m.group(1), m.group(2))
        if current_frame_id is None:
            raise ActionParseError("call-syntax action lacks frame_id and none was provided")
        return Action(**{**a.__dict__, "frame_id": current_frame_id})
    raise ActionParseError(f"no parseable action in model output: {text[:200]!r}")
