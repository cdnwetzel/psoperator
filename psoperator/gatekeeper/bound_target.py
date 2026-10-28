"""The bound-target gate: keys reach the application only on allow-listed paths.

The pilot application is driven by keystrokes through menu path codes, and one
wrong digit selects a different screen: a read-only report and a function that
processes data can sit one digit apart. So the gate is an allow-list, not a
deny-list, and it trusts no caller-supplied picture of the screen: the
gatekeeper observes the screen itself (an injected observer), immediately
before checking and again immediately before the key is sent.

A key is admitted only when every one of these holds:

1. it is one recognised key, not typed text or a chord;
2. the observation is fresh, of the bound main window of the bound process
   instance (pid and start time; Windows reuses pids);
3. that main window is the foreground window and the topmost window at the
   target point (an owned dialog or popup of the same process fails this);
4. the menu path is on the allow-list, the key is the one allowed at this
   step, and the screen's complete signature (every visible Edit's position,
   the hash of every label-class caption on screen, every labelled field's
   label hash and position, dialogs, focus) equals the step's expected one and
   none of the step's recorded neighbouring screens;
5. the target is a Win32 field of that instance that has keyboard focus, is
   the node the tree holds at that handle and geometry, contains the point,
   and is visible: every node on its path is visible and it lies inside the
   client area of every ancestor (a scrolled-out Edit still reports itself
   visible);
6. immediately before sending, a second observation shows the same windows,
   focus and screen.

Anything else is refused and audited with a fixed reason code. The audit keeps
validated identity, the frame hash, rectangles and recognised key names;
never text, and never a caller-supplied string verbatim.

The allow-list is private configuration (:meth:`AllowList.load`), validated
strictly; an empty allow-list refuses everything.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from psoperator.perception.win32_fields import (
    LABEL_CLASS,
    Rect,
    Win32Field,
    WindowNode,
    pair_fields,
)
from psoperator.runtime.actions import Action, ActionKind

_HASH = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9_.#:-]{1,64}")
_PATH = re.compile(r"[0-9A-Za-z-]{1,32}")
_KEYS = frozenset(
    {"ENTER", "ESC", "TAB", "SPACE", "BACKSPACE", "UP", "DOWN", "LEFT", "RIGHT"}
    | {f"F{i}" for i in range(1, 13)}
)


def valid_key(key: object) -> bool:
    """A key name the gate recognises: a digit, an upper-case letter or a
    named key. Anything else is refused and never audited verbatim."""
    return isinstance(key, str) and (key in _KEYS or re.fullmatch(r"[0-9A-Z]", key) is not None)


class Code(str, Enum):
    """Fixed reason codes: the audit records these, never free text."""

    NOT_KEY = "not-a-key-action"
    CHORD = "not-one-key"
    BAD_KEY = "key-not-recognised"
    STALE = "observation-stale"
    OBSERVE_FAILED = "observation-failed"
    INSTANCE = "wrong-instance"
    COVERED = "target-point-covered"
    NOT_FOREGROUND = "not-foreground"
    NO_PATH = "path-not-allowed"
    NO_STEP = "no-such-step"
    WRONG_KEY = "key-not-allowed-at-step"
    SCREEN = "screen-mismatch"
    NO_TARGET = "no-target"
    UNSUPPORTED = "unsupported-target"
    NOT_FOCUSED = "target-not-focused"
    TARGET_MISMATCH = "target-mismatch"
    HIDDEN = "target-hidden"
    CLIPPED = "target-clipped"
    GEOMETRY = "bad-geometry"
    CHANGED = "screen-changed"
    INVALID = "invalid-request"


@dataclass(frozen=True)
class Refusal:
    code: Code
    detail: str = ""  # for the caller; never audited


class AllowListError(Exception):
    """The allow-list cannot be read or is malformed; nothing is allowed."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def valid_rect(rect: object) -> bool:
    return (
        isinstance(rect, tuple)
        and len(rect) == 4
        and all(_is_int(v) for v in rect)
        and rect[2] > 0
        and rect[3] > 0
    )


@dataclass(frozen=True)
class ScreenSignature:
    """A screen as structure, never text. Rectangles are relative to the main
    window. ``edit_rects`` holds every visible Edit; ``captions`` the hash of
    every visible label-class caption on screen (screen-wide, so screens
    without fields, such as menus, are still told apart); ``labelled`` every
    paired field as (label hash, Edit rectangle). All are kept sorted, so
    positions and multiplicity count, not only sets."""

    owned_windows: int
    focus_class: str
    focus_rect: Rect
    edit_rects: tuple[Rect, ...]
    captions: tuple[str, ...]
    labelled: tuple[tuple[str, Rect], ...]

    def __post_init__(self) -> None:
        if not _is_int(self.owned_windows) or self.owned_windows < 0:
            raise ValueError("owned_windows must be a non-negative integer")
        if not isinstance(self.focus_class, str) or not _NAME.fullmatch(self.focus_class):
            raise ValueError("focus_class must be a window class name")
        if not valid_rect(self.focus_rect):
            raise ValueError("focus_rect must be four integers with positive size")
        if not isinstance(self.edit_rects, tuple) or not all(map(valid_rect, self.edit_rects)):
            raise ValueError("edit_rects must be a tuple of valid rectangles")
        if not isinstance(self.captions, tuple) or not all(
            isinstance(h, str) and _HASH.fullmatch(h) for h in self.captions
        ):
            raise ValueError("captions must be a tuple of 64-hex caption hashes")
        if not isinstance(self.labelled, tuple) or not all(
            isinstance(item, tuple)
            and len(item) == 2
            and isinstance(item[0], str)
            and _HASH.fullmatch(item[0])
            and valid_rect(item[1])
            for item in self.labelled
        ):
            raise ValueError("labelled must be a tuple of (64-hex label hash, rectangle)")
        object.__setattr__(self, "edit_rects", tuple(sorted(self.edit_rects)))
        object.__setattr__(self, "captions", tuple(sorted(self.captions)))
        object.__setattr__(self, "labelled", tuple(sorted(self.labelled)))


def signature_problem(expected: ScreenSignature, observed: ScreenSignature) -> str | None:
    """Which part of the screen differs, or None."""
    if observed.owned_windows != expected.owned_windows:
        return "dialogs"
    if (observed.focus_class, observed.focus_rect) != (expected.focus_class, expected.focus_rect):
        return "focus"
    if observed.edit_rects != expected.edit_rects:
        return "edits"
    if observed.captions != expected.captions:
        return "captions"
    if observed.labelled != expected.labelled:
        return "labels"
    return None


def _relative(rect: Rect, origin: tuple[int, int]) -> Rect:
    return (rect[0] - origin[0], rect[1] - origin[1], rect[2], rect[3])


def _visible_nodes(root: WindowNode):
    """Visible descendants of ``root`` (a hidden window hides its subtree)."""
    stack = list(reversed(root.children))
    while stack:
        node = stack.pop()
        if node.visible:
            yield node
            stack.extend(reversed(node.children))


def signature_of(
    tree: WindowNode,
    focus_hwnd: int,
    owned_windows: int,
    *,
    pid: int,
    process_started: int,
    process_image: str,
    label_class: str | None = None,
) -> ScreenSignature:
    """The signature of an observed main-window tree. Raises if the focus is
    not a visible control inside the tree."""
    origin = (tree.rect[0], tree.rect[1])
    focus = next((n for n in _visible_nodes(tree) if n.hwnd == focus_hwnd), None)
    if focus is None:
        raise ValueError("keyboard focus is not on a visible control of the main window")
    edits = tuple(_relative(n.rect, origin) for n in _visible_nodes(tree) if n.class_name == "Edit")
    wanted = label_class or LABEL_CLASS
    captions = tuple(
        n.name_hash
        for n in _visible_nodes(tree)
        if n.class_name == wanted and n.name_hash is not None
    )
    kwargs = {"label_class": label_class} if label_class else {}
    scan = pair_fields(
        tree, pid=pid, process_started=process_started, process_image=process_image, **kwargs
    )
    return ScreenSignature(
        owned_windows=owned_windows,
        focus_class=focus.class_name,
        focus_rect=_relative(focus.rect, origin),
        edit_rects=edits,
        captions=captions,
        labelled=tuple((f.label_hash, f.rect) for f in scan.fields),
    )


@dataclass(frozen=True)
class AllowedStep:
    """One step: the screen it must be on, the one key it allows, and the
    recorded signatures of neighbouring screens it must be told apart from
    (e.g. the screen one wrong digit away)."""

    expected: ScreenSignature
    key: str
    neighbours: tuple[ScreenSignature, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.expected, ScreenSignature):
            raise AllowListError("a step needs a complete expected screen signature")
        if not self.expected.captions:
            raise AllowListError(
                "a step's expected screen needs screen-specific caption hashes; "
                "counts and focus alone cannot tell screens apart"
            )
        if not valid_key(self.key):
            raise AllowListError("a step needs a recognised key")
        if not isinstance(self.neighbours, tuple) or not all(
            isinstance(n, ScreenSignature) for n in self.neighbours
        ):
            raise AllowListError("neighbours must be a tuple of screen signatures")
        for neighbour in self.neighbours:
            if signature_problem(self.expected, neighbour) is None:
                raise AllowListError("a recorded neighbouring screen equals the expected one")


@dataclass(frozen=True)
class AllowedPath:
    path: str
    steps: tuple[AllowedStep, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not _PATH.fullmatch(self.path):
            raise AllowListError("a path needs a menu path code")
        if not isinstance(self.steps, tuple) or not self.steps:
            raise AllowListError(f"path {self.path!r} has no steps")
        if not all(isinstance(s, AllowedStep) for s in self.steps):
            raise AllowListError(f"path {self.path!r} has a step that is not an AllowedStep")


def _no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise AllowListError(f"allow-list repeats the member {key!r}")
        seen[key] = value
    return seen


def _exact(obj: object, keys: set[str], where: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != keys:
        raise AllowListError(f"{where} must have exactly the fields {sorted(keys)}")
    return obj


def _rect_from(value: object, where: str) -> Rect:
    rect = tuple(value) if isinstance(value, list) else None
    if rect is None or not valid_rect(rect):
        raise AllowListError(f"{where}: a rectangle must be four integers with positive size")
    return rect


def _signature_from(data: object, where: str) -> ScreenSignature:
    fields = {"owned_windows", "focus_class", "focus_rect", "edit_rects", "captions", "labelled"}
    data = _exact(data, fields, f"{where} expected")
    if not all(isinstance(data[k], list) for k in ("edit_rects", "captions", "labelled")):
        raise AllowListError(f"{where} expected: edit_rects, captions and labelled must be lists")
    labelled = []
    for item in data["labelled"]:
        if not isinstance(item, list) or len(item) != 2:
            raise AllowListError(f"{where} expected: labelled items are [hash, rectangle]")
        labelled.append((item[0], _rect_from(item[1], where)))
    try:
        return ScreenSignature(
            owned_windows=data["owned_windows"],
            focus_class=data["focus_class"],
            focus_rect=_rect_from(data["focus_rect"], where),
            edit_rects=tuple(_rect_from(r, where) for r in data["edit_rects"]),
            captions=tuple(data["captions"]),
            labelled=tuple(labelled),
        )
    except ValueError as exc:
        raise AllowListError(f"{where} expected: {exc}") from exc


class AllowList:
    """Menu paths explicitly marked read-only, with each step's screen and key."""

    def __init__(self, paths: Iterable[AllowedPath]) -> None:
        self._paths: dict[str, AllowedPath] = {}
        seen: list[ScreenSignature] = []
        for entry in paths:
            if not isinstance(entry, AllowedPath):
                raise AllowListError("allow-list entries must be AllowedPath")
            if entry.path in self._paths:
                raise AllowListError(f"path {entry.path!r} is listed twice")
            for step in entry.steps:
                if step.expected in seen:
                    raise AllowListError(
                        "two steps expect the same screen signature; the gate could "
                        "not tell them apart"
                    )
                seen.append(step.expected)
            self._paths[entry.path] = entry

    @classmethod
    def load(cls, path: Path | str) -> "AllowList":
        """Load the private allow-list JSON. Any doubt about it refuses to load."""
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise AllowListError(f"allow-list {path} is unreadable: {exc}") from exc
        try:
            data = json.loads(text, object_pairs_hook=_no_duplicates)
        except ValueError as exc:
            raise AllowListError(f"allow-list {path} is unreadable: {exc}") from exc
        data = _exact(data, {"paths"}, "the allow-list")
        if not isinstance(data["paths"], list):
            raise AllowListError("the allow-list paths must be a list")
        entries = []
        for item in data["paths"]:
            item = _exact(item, {"path", "steps"}, "a path entry")
            if not isinstance(item["steps"], list) or not item["steps"]:
                raise AllowListError(f"path {item['path']!r} has no steps")
            steps = []
            for i, step in enumerate(item["steps"]):
                where = f"path {item['path']!r} step {i}"
                keys = (
                    {"key", "expected", "neighbours"}
                    if "neighbours" in step
                    else {"key", "expected"}
                )
                step = _exact(step, keys, where)
                neighbours = step.get("neighbours", [])
                if not isinstance(neighbours, list):
                    raise AllowListError(f"{where}: neighbours must be a list")
                steps.append(
                    AllowedStep(
                        _signature_from(step["expected"], where),
                        step["key"],
                        tuple(_signature_from(n, f"{where} neighbour") for n in neighbours),
                    )
                )
            entries.append(AllowedPath(item["path"], tuple(steps)))
        return cls(entries)

    def problem(self, path: str, step: int, key: str, observed: ScreenSignature) -> Refusal | None:
        entry = self._paths.get(path)
        if entry is None:
            return Refusal(Code.NO_PATH)
        if not _is_int(step) or not 0 <= step < len(entry.steps):
            return Refusal(Code.NO_STEP)
        allowed = entry.steps[step]
        if key != allowed.key:
            return Refusal(Code.WRONG_KEY, f"step {step} allows only {allowed.key}")
        if any(signature_problem(n, observed) is None for n in allowed.neighbours):
            return Refusal(Code.SCREEN, "a recorded neighbouring screen")
        mismatch = signature_problem(allowed.expected, observed)
        if mismatch is not None:
            return Refusal(Code.SCREEN, mismatch)
        return None


@dataclass(frozen=True)
class Observation:
    """What the gatekeeper's own observer saw, and when (monotonic seconds).
    ``topmost_hwnd`` is the top-level window at ``point``; an owned popup is
    its own top-level window, so it never equals the main window."""

    at: float
    main_hwnd: int
    instance: tuple[int, int]
    foreground_hwnd: int
    topmost_hwnd: int
    focus_hwnd: int
    point: tuple[int, int]
    signature: ScreenSignature
    tree: WindowNode


@dataclass(frozen=True)
class OcrBox:
    """A target read by OCR: a rectangle in the frame it was seen in. Not a
    valid key target: keys go to the focused control."""

    rect: Rect


@dataclass(frozen=True)
class BoundKeyRequest:
    action: Action
    path: str
    step: int
    app_instance: tuple[int, int]
    main_hwnd: int
    target: Win32Field | OcrBox | None


def _path_to(root: WindowNode, hwnd: int) -> list[WindowNode] | None:
    stack = [(root, [root])]
    while stack:
        node, path = stack.pop()
        if node.hwnd == hwnd:
            return path
        stack.extend((child, [*path, child]) for child in node.children)
    return None


def _inside(inner: Rect, outer: Rect) -> bool:
    return (
        inner[0] >= outer[0]
        and inner[1] >= outer[1]
        and inner[0] + inner[2] <= outer[0] + outer[2]
        and inner[1] + inner[3] <= outer[1] + outer[3]
    )


def _point_in(point: tuple[int, int], rect: Rect) -> bool:
    return rect[0] <= point[0] < rect[0] + rect[2] and rect[1] <= point[1] < rect[1] + rect[3]


def _valid_field(field: Win32Field) -> bool:
    return (
        all(_is_int(v) for v in (field.pid, field.process_started, field.hwnd))
        and isinstance(field.process_image, str)
        and _NAME.fullmatch(field.process_image) is not None
        and isinstance(field.class_path, tuple)
        and 0 < len(field.class_path) <= 16
        and all(isinstance(c, str) and _NAME.fullmatch(c) for c in field.class_path)
        and isinstance(field.label_hash, str)
        and _HASH.fullmatch(field.label_hash) is not None
        and all(map(valid_rect, (field.rect, field.label_rect, field.screen_rect)))
    )


def target_problem(target: object, request: BoundKeyRequest, obs: Observation) -> Refusal | None:
    """Whether the target is the focused, visible field it claims to be."""
    if target is None:
        return Refusal(Code.NO_TARGET)
    if not isinstance(target, Win32Field):
        return Refusal(Code.UNSUPPORTED)
    if not _valid_field(target):
        return Refusal(Code.INVALID, "the target's identity is malformed")
    if target.instance != request.app_instance:
        return Refusal(Code.INSTANCE)
    if target.hwnd != obs.focus_hwnd:
        return Refusal(Code.NOT_FOCUSED)
    path = _path_to(obs.tree, target.hwnd)
    if path is None or len(path) < 2:
        return Refusal(Code.TARGET_MISMATCH, "not a control of the main window")
    node = path[-1]
    if node.class_name != "Edit" or node.rect != target.screen_rect:
        return Refusal(Code.TARGET_MISMATCH, "class or geometry differs")
    if not _point_in(obs.point, node.rect):
        return Refusal(Code.TARGET_MISMATCH, "the checked point is outside the field")
    if not all(n.visible for n in path):
        return Refusal(Code.HIDDEN)
    for ancestor in path[:-1]:
        if ancestor.client_rect is None or not valid_rect(ancestor.client_rect):
            return Refusal(Code.GEOMETRY, "an ancestor's client area is unknown or invalid")
        if not valid_rect(node.rect) or not _inside(node.rect, ancestor.client_rect):
            return Refusal(Code.CLIPPED)
    return None


def bound_key_problem(
    request: BoundKeyRequest,
    allow: AllowList,
    obs: Observation,
    *,
    now: float,
    max_age_s: float,
) -> Refusal | None:
    """Why the key may not be sent on this observation, or None."""
    action = request.action
    if action.kind is not ActionKind.KEY:
        return Refusal(Code.NOT_KEY)
    if len(action.keys) != 1:
        return Refusal(Code.CHORD)
    key = action.keys[0]
    if not valid_key(key):
        return Refusal(Code.BAD_KEY)
    if not 0 <= now - obs.at <= max_age_s:
        return Refusal(Code.STALE)
    if obs.main_hwnd != request.main_hwnd or obs.instance != request.app_instance:
        return Refusal(Code.INSTANCE)
    if obs.topmost_hwnd != obs.main_hwnd:
        return Refusal(Code.COVERED)
    if obs.foreground_hwnd != obs.main_hwnd:
        return Refusal(Code.NOT_FOREGROUND)
    refusal = allow.problem(request.path, request.step, key, obs.signature)
    if refusal is not None:
        return refusal
    return target_problem(request.target, request, obs)


def unchanged(first: Observation, second: Observation) -> bool:
    """Whether a second observation shows the same windows, focus and screen."""
    return (
        second.main_hwnd,
        second.instance,
        second.foreground_hwnd,
        second.topmost_hwnd,
        second.focus_hwnd,
        second.point,
        second.signature,
    ) == (
        first.main_hwnd,
        first.instance,
        first.foreground_hwnd,
        first.topmost_hwnd,
        first.focus_hwnd,
        first.point,
        first.signature,
    )


def _safe(value: object, pattern: re.Pattern) -> str:
    return value if isinstance(value, str) and pattern.fullmatch(value) else "<invalid>"


def _rect_list(value: object) -> list | None:
    return list(value) if valid_rect(value) else None


def audit_record(target: object, frame_hash: str) -> dict:
    """What the audit keeps about a target: validated identity, the frame hash
    and rectangles. Never a label, a value, or any unvalidated string."""
    frame = _safe(frame_hash, _HASH)
    if isinstance(target, OcrBox):
        return {"kind": "ocr-box", "frame_hash": frame, "rect": _rect_list(target.rect)}
    if not isinstance(target, Win32Field):
        return {"kind": "none", "frame_hash": frame}
    instance = target.instance
    return {
        "kind": "win32-field",
        "frame_hash": frame,
        "process_image": _safe(target.process_image, _NAME),
        "instance": list(instance) if all(_is_int(v) for v in instance) else None,
        "class_path": [_safe(c, _NAME) for c in target.class_path][:16],
        "label_hash": _safe(target.label_hash, _HASH),
        "rect": _rect_list(target.rect),
        "label_rect": _rect_list(target.label_rect),
        "screen_rect": _rect_list(target.screen_rect),
    }


def audited_keys(action: Action) -> list[str]:
    """Key names for the audit: recognised names only."""
    return [k if valid_key(k) else "<invalid>" for k in action.keys][:4]
