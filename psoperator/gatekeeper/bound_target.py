"""The bound-target gate: keys reach the application only on allow-listed paths.

The pilot application is driven by keystrokes through menu path codes, and one
wrong digit selects a different screen: a read-only report and a function that
processes data can sit one digit apart. So the gate is an allow-list, not a
deny-list, and it trusts no caller-supplied picture of the screen. The
gatekeeper is constructed with a trusted observer (the live one is
``perception.win32_state.observe``) and calls it immediately before checking and
again immediately before the key is sent.

A key is admitted only when every one of these holds:

1. it is one recognised key, not typed text or a chord;
2. the observation is fresh, internally consistent, and of the bound main
   window of the bound process instance (pid and start time; Windows reuses
   pids);
3. no menu, move/size or mouse-capture mode is active in the main window's
   thread (any of them can take the key instead of the focused control), and
   no Shift, Ctrl, Alt or Windows key is held (it would turn the key into a
   chord);
4. the main window is the foreground window and the top-level window at the
   target point (an owned dialog or popup of the same process fails this);
5. the menu path is on the allow-list, the key is the one allowed at this
   step, and the screen's complete signature equals the step's expected one
   and none of its recorded neighbouring screens (every step must record at
   least one, e.g. the screen one wrong digit away);
6. the target is the focused, visible control the observation itself shows:
   a labelled Win32 field equal to one the observed tree yields, or the
   focused Edit at the step's rectangle; it contains the point and lies
   inside the client area of every ancestor (a scrolled-out Edit still
   reports itself visible);
7. a second observation, taken just before sending, shows the same windows,
   focus, input modes and screen.

Anything else is refused and audited with a fixed reason code. The audited
identity is built from the observation, never from the caller's request.

The allow-list is private configuration (:meth:`AllowList.load`), validated
strictly; an empty allow-list refuses everything.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
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
    named key. Anything else is refused and never audited verbatim. Only an
    exact ``str``: a subclass can compare equal to a name and hold other text."""
    return type(key) is str and (key in _KEYS or re.fullmatch(r"[0-9A-Z]", key) is not None)


class Code(str, Enum):
    """Fixed reason codes: the audit records these, never free text."""

    NOT_KEY = "not-a-key-action"
    CHORD = "not-one-key"
    BAD_KEY = "key-not-recognised"
    NO_OBSERVER = "no-observer"
    STALE = "observation-stale"
    OBSERVE_FAILED = "observation-failed"
    INSTANCE = "wrong-instance"
    WRONG_APP = "wrong-application"
    INPUT_MODE = "input-mode-active"
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
    RECIPIENT_CHANGED = "recipient-changed-before-send"
    SENT_THEN_CHANGED = "recipient-changed-after-send"
    UNBOUND_INPUT = "input-not-bound"
    MODIFIER_HELD = "modifier-held"
    KEYBOARD_UNREADABLE = "keyboard-unreadable"


@dataclass(frozen=True)
class Refusal:
    code: Code
    detail: str = ""  # for the caller; never audited


# The codes a live reading may raise as a KeyStateRefusal.
KEY_STATE_CODES = frozenset({Code.MODIFIER_HELD, Code.KEYBOARD_UNREADABLE})


class KeyStateRefusal(Exception):
    """A live reading found a modifier key held, or could not establish that
    the keyboard state is readable: raised with its fixed code so that the
    refusal keeps that code instead of becoming a generic failed reading."""

    def __init__(self, code: Code) -> None:
        super().__init__(code.value)
        self.code = code


def key_state_code(error: BaseException) -> Code | None:
    """The fixed code carried by ``error`` if it is a KeyStateRefusal with one
    of :data:`KEY_STATE_CODES`, else None. Safe for any exception."""
    if not isinstance(error, KeyStateRefusal):
        return None
    try:
        code = error.code
    except Exception:
        return None
    return code if type(code) is Code and code in KEY_STATE_CODES else None


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


def _hash_rect_pairs(value: object) -> bool:
    return isinstance(value, tuple) and all(
        isinstance(item, tuple)
        and len(item) == 2
        and isinstance(item[0], str)
        and _HASH.fullmatch(item[0]) is not None
        and valid_rect(item[1])
        for item in value
    )


@dataclass(frozen=True)
class ScreenSignature:
    """A screen as structure, never text. Rectangles are relative to the main
    window. ``edit_rects`` holds every visible Edit; ``captions`` every visible
    label-class caption on screen as (hash, rectangle), so screens without
    fields, such as menus, are still told apart and placement counts;
    ``labelled`` every paired field as (label hash, Edit rectangle). All are
    kept sorted, so positions and multiplicity count, not only sets."""

    owned_windows: int
    focus_class: str
    focus_rect: Rect
    edit_rects: tuple[Rect, ...]
    captions: tuple[tuple[str, Rect], ...]
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
        if not _hash_rect_pairs(self.captions):
            raise ValueError("captions must be a tuple of (64-hex hash, rectangle)")
        if not _hash_rect_pairs(self.labelled):
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


def observed_fields(
    tree: WindowNode, instance: tuple[int, int], image: str, label_class: str | None = None
) -> tuple[Win32Field, ...]:
    """The labelled fields the observed tree yields, with observed identity."""
    kwargs = {"label_class": label_class} if label_class else {}
    return pair_fields(
        tree, pid=instance[0], process_started=instance[1], process_image=image, **kwargs
    ).fields


def signature_of(
    tree: WindowNode,
    focus_hwnd: int,
    owned_windows: int,
    *,
    instance: tuple[int, int],
    image: str,
    label_class: str | None = None,
) -> ScreenSignature:
    """The signature of an observed main-window tree. Raises if the focus is
    not a visible control inside the tree."""
    origin = (tree.rect[0], tree.rect[1])
    nodes = list(_visible_nodes(tree))
    focus = next((n for n in nodes if n.hwnd == focus_hwnd), None)
    if focus is None:
        raise ValueError("keyboard focus is not on a visible control of the main window")
    wanted = label_class or LABEL_CLASS
    return ScreenSignature(
        owned_windows=owned_windows,
        focus_class=focus.class_name,
        focus_rect=_relative(focus.rect, origin),
        edit_rects=tuple(_relative(n.rect, origin) for n in nodes if n.class_name == "Edit"),
        captions=tuple(
            (n.name_hash, _relative(n.rect, origin))
            for n in nodes
            if n.class_name == wanted and n.name_hash is not None
        ),
        labelled=tuple(
            (f.label_hash, f.rect) for f in observed_fields(tree, instance, image, label_class)
        ),
    )


@dataclass(frozen=True)
class AllowedStep:
    """One step: the screen it must be on, the one key it allows, and the
    recorded signatures of neighbouring screens it must be told apart from
    (at least one, e.g. the screen one wrong digit away)."""

    expected: ScreenSignature
    key: str
    neighbours: tuple[ScreenSignature, ...]

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
        if (
            not isinstance(self.neighbours, tuple)
            or not self.neighbours
            or not all(isinstance(n, ScreenSignature) for n in self.neighbours)
        ):
            raise AllowListError(
                "a step needs at least one recorded neighbouring screen, as evidence "
                "that its signature tells it apart from a dangerous neighbour"
            )
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


def _pairs_from(value: object, where: str) -> tuple[tuple[str, Rect], ...]:
    if not isinstance(value, list):
        raise AllowListError(f"{where}: must be a list of [hash, rectangle]")
    pairs = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise AllowListError(f"{where}: items are [hash, rectangle]")
        pairs.append((item[0], _rect_from(item[1], where)))
    return tuple(pairs)


def _signature_from(data: object, where: str) -> ScreenSignature:
    fields = {"owned_windows", "focus_class", "focus_rect", "edit_rects", "captions", "labelled"}
    data = _exact(data, fields, f"{where} screen")
    if not isinstance(data["edit_rects"], list):
        raise AllowListError(f"{where} screen: edit_rects must be a list")
    try:
        return ScreenSignature(
            owned_windows=data["owned_windows"],
            focus_class=data["focus_class"],
            focus_rect=_rect_from(data["focus_rect"], where),
            edit_rects=tuple(_rect_from(r, where) for r in data["edit_rects"]),
            captions=_pairs_from(data["captions"], f"{where} captions"),
            labelled=_pairs_from(data["labelled"], f"{where} labelled"),
        )
    except ValueError as exc:
        raise AllowListError(f"{where} screen: {exc}") from exc


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
                raise AllowListError("a path entry has no steps")
            steps = []
            for i, step in enumerate(item["steps"]):
                where = f"step {i}"
                step = _exact(step, {"key", "expected", "neighbours"}, where)
                if not isinstance(step["neighbours"], list):
                    raise AllowListError(f"{where}: neighbours must be a list")
                steps.append(
                    AllowedStep(
                        _signature_from(step["expected"], where),
                        step["key"],
                        tuple(_signature_from(n, f"{where} neighbour") for n in step["neighbours"]),
                    )
                )
            entries.append(AllowedPath(item["path"], tuple(steps)))
        return cls(entries)

    def problem(self, path: str, step: int, key: str, observed: ScreenSignature) -> Refusal | None:
        entry = self._paths.get(path) if isinstance(path, str) else None
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
    """What the gatekeeper's trusted observer saw, and when (monotonic
    seconds). ``point`` is the centre of the focused control (keys go to the
    focused control) and ``topmost_hwnd`` the top-level window there; an owned
    popup is its own top-level window, so it never equals the main window.
    ``input_clear`` is False while a menu, move/size or mouse-capture mode is
    active in the main window's thread; ``modifiers_clear`` is False while a
    Shift, Ctrl, Alt or Windows key is held (SendInput keeps the keyboard
    state, so ENTER would arrive as a chord)."""

    at: float
    main_hwnd: int
    instance: tuple[int, int]
    image: str
    foreground_hwnd: int
    topmost_hwnd: int
    focus_hwnd: int
    input_clear: bool
    modifiers_clear: bool
    point: tuple[int, int]
    signature: ScreenSignature
    tree: WindowNode


@dataclass(frozen=True)
class FocusedEdit:
    """A key target that is the focused, unlabelled Edit at a rectangle
    relative to the main window (e.g. a menu's key-entry or search box)."""

    rect: Rect


@dataclass(frozen=True)
class OcrBox:
    """A target read by OCR. Not a valid key target: keys go to the focused
    control."""

    rect: Rect


@dataclass(frozen=True)
class BoundKeyRequest:
    """What a caller may say about a key: which, where in the allow-list, and
    aimed at which control. The application window, its process instance and
    the screen are never part of the request: they are the gatekeeper's
    configuration and observation."""

    action: Action
    path: str
    step: int
    target: Win32Field | FocusedEdit | OcrBox | None


_TARGET_TYPES = (Win32Field, FocusedEdit, OcrBox, type(None))

_CLICK_FIELDS = frozenset({"target_element_id", "x", "y", "button"})
# The optional fields each kind may carry; every other one must hold its default.
_KIND_FIELDS = {
    ActionKind.CLICK: _CLICK_FIELDS,
    ActionKind.RIGHT_CLICK: _CLICK_FIELDS,
    ActionKind.DOUBLE_CLICK: _CLICK_FIELDS,
    ActionKind.TYPE: frozenset({"target_element_id", "text"}),
    ActionKind.KEY: frozenset({"target_element_id", "keys"}),
    ActionKind.SCROLL: frozenset({"target_element_id", "x", "y", "amount"}),
    ActionKind.DRAG: frozenset({"target_element_id", "x", "y", "to_x", "to_y"}),
    ActionKind.WAIT: frozenset({"seconds"}),
    ActionKind.DONE: frozenset(),
    ActionKind.FAIL: frozenset({"reason"}),
}
# Exact built-in types only: a subclass can hold other text or behave differently.
_FIELD_TYPES = {
    "target_element_id": (str,),
    "x": (int,),
    "y": (int,),
    "to_x": (int,),
    "to_y": (int,),
    "text": (str,),
    "amount": (int,),
    "seconds": (int, float),
    "button": (str,),
    "reason": (str,),
}
_DEFAULTS = {name: None for name in _FIELD_TYPES} | {"button": "left"}


def trusted_action(action: object) -> Action:
    """A private copy of ``action``, which must be exactly an :class:`Action`
    (frozen, so its fields cannot change between reads) with an
    :class:`ActionKind`, a tuple of key names and exact built-in types in every
    field. Fields its kind does not use are dropped from the copy, so they
    reach neither risk classification, the executor nor the audit. Raises
    ``ValueError`` otherwise."""
    if type(action) is not Action:
        raise ValueError("the action must be an Action")
    keys = action.keys
    if type(action.kind) is not ActionKind:
        raise ValueError("the action kind must be an ActionKind")
    if type(action.frame_id) is not int:
        raise ValueError("the frame id must be an int")
    if type(keys) is not tuple or not all(type(k) is str for k in keys):
        raise ValueError("the keys must be a tuple of names")
    used = _KIND_FIELDS[action.kind]
    dropped = {}
    for name, types in _FIELD_TYPES.items():
        value = getattr(action, name)
        if value is not None and type(value) not in types:
            raise ValueError("a field has the wrong type")
        if name not in used:
            dropped[name] = _DEFAULTS[name]
    if "keys" not in used:
        keys = ()
    # Nobody else holds a reference to the copy that is checked and executed.
    return replace(action, keys=keys, **dropped)


def normalized(request: object) -> BoundKeyRequest:
    """Read each field of ``request`` exactly once into a fresh, immutable
    request, so the values checked are the values executed. Raises
    ``ValueError`` for anything that is not plainly a key request."""
    action, path, step, target = request.action, request.path, request.step, request.target
    action = trusted_action(action)
    if type(path) is not str or not _is_int(step) or type(target) not in _TARGET_TYPES:
        raise ValueError("the path, step or target is malformed")
    return BoundKeyRequest(action=action, path=path, step=step, target=target)


def recipient_of(obs: Observation) -> tuple:
    """Who would receive a key, and as what, as the observation saw it: the
    foreground window, the focused control, whether no menu/move-size/capture
    mode is active, the focused control's centre, the top-level window there,
    and whether no modifier key is held (last). The same order as a live
    recipient reading."""
    return (
        obs.foreground_hwnd,
        obs.focus_hwnd,
        obs.input_clear,
        obs.point,
        obs.topmost_hwnd,
        obs.modifiers_clear,
    )


def recipient_problem(reading: object, approved: tuple, changed: Code, held: Code) -> Code | None:
    """Why a live recipient reading may not stand for ``approved`` (the
    approved observation's :func:`recipient_of`): ``held`` if a modifier key
    is down, ``changed`` if anything else differs or the reading is malformed,
    or None."""
    if type(reading) is not tuple or len(reading) != len(approved):
        return changed
    if reading[-1] is not True:
        return held
    return None if reading == approved else changed


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


def _safe(value: object, pattern: re.Pattern) -> str:
    return value if type(value) is str and pattern.fullmatch(value) else "<invalid>"


def audited_hash(value: object) -> str:
    """A 64-hex hash for the audit, or ``<invalid>``. Safe for any input."""
    return _safe(value, _HASH)


def _rect_list(value: object) -> list | None:
    exact = valid_rect(value) and all(type(v) is int for v in value)
    return list(value) if exact else None


def _verified_target(target: object, obs: Observation) -> tuple[dict | None, Refusal | None]:
    """The audited identity of the target, built from the observation, or why
    the target is not the focused, visible control the observation shows."""
    if target is None:
        return None, Refusal(Code.NO_TARGET)
    if not isinstance(target, (Win32Field, FocusedEdit)):
        return None, Refusal(Code.UNSUPPORTED)
    path = _path_to(obs.tree, obs.focus_hwnd)
    if path is None or len(path) < 2:
        return None, Refusal(Code.NOT_FOCUSED, "focus is not on a control of the main window")
    node = path[-1]
    origin = (obs.tree.rect[0], obs.tree.rect[1])
    if node.class_name != "Edit" or not valid_rect(node.rect):
        return None, Refusal(Code.TARGET_MISMATCH, "the focused control is not an Edit")
    if isinstance(target, Win32Field):
        if target.hwnd != obs.focus_hwnd:
            return None, Refusal(Code.NOT_FOCUSED)
        matches = [
            f
            for f in observed_fields(obs.tree, obs.instance, obs.image)
            if f.hwnd == node.hwnd and f == target and f.screen_rect == target.screen_rect
        ]
        if len(matches) != 1:
            return None, Refusal(Code.TARGET_MISMATCH, "not a field the observation shows")
        field = matches[0]
        identity = {
            "kind": "win32-field",
            "class_path": [_safe(c, _NAME) for c in field.class_path][:16],
            "label_hash": _safe(field.label_hash, _HASH),
            "rect": _rect_list(field.rect),
            "label_rect": _rect_list(field.label_rect),
        }
    else:
        if not valid_rect(target.rect) or _relative(node.rect, origin) != target.rect:
            return None, Refusal(Code.NOT_FOCUSED, "the focused Edit is elsewhere")
        identity = {
            "kind": "focused-edit",
            "class_path": [_safe(n.class_name, _NAME) for n in path][:16],
            "rect": _rect_list(_relative(node.rect, origin)),
        }
    if not _point_in(obs.point, node.rect):
        return None, Refusal(Code.TARGET_MISMATCH, "the checked point is outside the field")
    if not all(n.visible for n in path):
        return None, Refusal(Code.HIDDEN)
    for ancestor in path[:-1]:
        if ancestor.client_rect is None or not valid_rect(ancestor.client_rect):
            return None, Refusal(Code.GEOMETRY, "an ancestor's client area is unknown or invalid")
        if not _inside(node.rect, ancestor.client_rect):
            return None, Refusal(Code.CLIPPED)
    identity.update(
        process_image=_safe(obs.image, _NAME),
        instance=list(obs.instance),
        screen_rect=_rect_list(node.rect),
    )
    return identity, None


def bound_key_problem(
    request: BoundKeyRequest,
    allow: AllowList,
    obs: Observation,
    *,
    now: float,
    max_age_s: float,
    app_image: str,
    main_hwnd: int,
    instance: tuple[int, int],
) -> tuple[dict | None, Refusal | None]:
    """The observed identity of the target and None, or None and why the key
    may not be sent on this observation."""
    action = request.action
    if getattr(action, "kind", None) is not ActionKind.KEY:
        return None, Refusal(Code.NOT_KEY)
    keys = getattr(action, "keys", None)
    if not isinstance(keys, tuple) or len(keys) != 1:
        return None, Refusal(Code.CHORD)
    key = keys[0]
    if not valid_key(key):
        return None, Refusal(Code.BAD_KEY)
    if not 0 <= now - obs.at <= max_age_s:
        return None, Refusal(Code.STALE)
    if obs.main_hwnd != main_hwnd or obs.instance != instance:
        return None, Refusal(Code.INSTANCE)
    if not isinstance(app_image, str) or obs.image.lower() != app_image.lower():
        return None, Refusal(Code.WRONG_APP)
    if obs.input_clear is not True:
        return None, Refusal(Code.INPUT_MODE)
    if obs.modifiers_clear is not True:
        return None, Refusal(Code.MODIFIER_HELD)
    if obs.topmost_hwnd != obs.main_hwnd:
        return None, Refusal(Code.COVERED)
    if obs.foreground_hwnd != obs.main_hwnd:
        return None, Refusal(Code.NOT_FOREGROUND)
    refusal = allow.problem(request.path, request.step, key, obs.signature)
    if refusal is not None:
        return None, refusal
    return _verified_target(request.target, obs)


def unchanged(first: Observation, second: Observation) -> bool:
    """Whether a second observation shows the same windows, focus, input modes
    and screen."""
    keys = (
        "main_hwnd",
        "instance",
        "image",
        "foreground_hwnd",
        "topmost_hwnd",
        "focus_hwnd",
        "input_clear",
        "modifiers_clear",
        "point",
        "signature",
    )
    return all(getattr(first, k) == getattr(second, k) for k in keys)


def unverified_record(target: object, frame_hash: object) -> dict:
    """What the audit keeps about a target before it is verified against an
    observation: its kind and the frame hash, nothing it claims about itself.
    Safe for any input."""
    kind = {
        Win32Field: "win32-field",
        FocusedEdit: "focused-edit",
        OcrBox: "ocr-box",
    }.get(type(target), "none")
    return {"kind": kind, "verified": False, "frame_hash": _safe(frame_hash, _HASH)}


def audited_keys(action: object) -> list[str]:
    """Key names for the audit: recognised names only, safe for any input."""
    try:
        keys = action.keys
    except Exception:
        keys = None
    if type(keys) is not tuple:
        return ["<invalid>"]
    return [k if valid_key(k) else "<invalid>" for k in keys][:4]
