"""The bound-target gate: keys reach the application only on allow-listed paths.

The pilot application is driven by keystrokes through menu path codes, and one
wrong digit selects a different screen: a read-only report and a function that
processes data can sit one digit apart. So the gate is an allow-list, not a
deny-list. A key is admitted only when every one of these holds:

1. it is a single key, not typed text or a chord;
2. the application's bound process instance (pid and start time; Windows reuses
   pids) is the foreground window and owns the topmost window at the target
   point, otherwise the refusal names the process in the way;
3. the menu path is on the allow-list, the key is the one allowed at this step,
   and the screen's window-tree signature matches the step's expected one;
4. a bound Win32 field belongs to the bound instance and lies inside the
   visible client area of every ancestor (a scrolled-out Edit still reports
   itself visible).

Anything else is refused, and the refusal is audited like a decision. The audit
records the target's identity, the frame hash and rectangles, never text.

The allow-list itself is private configuration (:meth:`AllowList.load`), and
an empty allow-list refuses everything.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, fields
from pathlib import Path

from psoperator.perception.win32_fields import Rect, Win32Field, WindowNode
from psoperator.runtime.actions import Action, ActionKind


class AllowListError(Exception):
    """The allow-list file cannot be read or is malformed; nothing is allowed."""


@dataclass(frozen=True)
class ScreenSignature:
    """What a screen looks like as structure, never text.

    ``paired`` and ``label_hashes`` (hashes of the label panels' internal
    names) are None until recorded for a step; the counts and the focus are
    always compared. Rectangles are relative to the top-level window."""

    visible_edits: int
    owned_windows: int
    focus_class: str | None
    focus_rect: Rect | None
    paired: int | None = None
    label_hashes: frozenset[str] | None = None


def signature_problem(expected: ScreenSignature, observed: ScreenSignature) -> str | None:
    """Why ``observed`` is not the expected screen, or None."""
    if observed.visible_edits != expected.visible_edits:
        return f"{observed.visible_edits} visible Edits, expected {expected.visible_edits}"
    if observed.owned_windows != expected.owned_windows:
        return (
            f"{observed.owned_windows} dialog or owned windows open, "
            f"expected {expected.owned_windows}"
        )
    if (observed.focus_class, observed.focus_rect) != (expected.focus_class, expected.focus_rect):
        return (
            f"focus is {observed.focus_class} at {observed.focus_rect}, "
            f"expected {expected.focus_class} at {expected.focus_rect}"
        )
    if expected.paired is not None and observed.paired != expected.paired:
        return f"{observed.paired} paired fields, expected {expected.paired}"
    if expected.label_hashes is not None and observed.label_hashes != expected.label_hashes:
        seen = observed.label_hashes or frozenset()
        return (
            f"field label hashes differ ({len(seen - expected.label_hashes)} unexpected, "
            f"{len(expected.label_hashes - seen)} missing)"
        )
    return None


@dataclass(frozen=True)
class AllowedStep:
    expected: ScreenSignature
    key: str


@dataclass(frozen=True)
class AllowedPath:
    path: str
    steps: tuple[AllowedStep, ...]


_SIGNATURE_FIELDS = {f.name for f in fields(ScreenSignature)}


def _signature_from(data: object, where: str) -> ScreenSignature:
    if not isinstance(data, dict):
        raise AllowListError(f"{where}: expected must be an object")
    unknown = set(data) - _SIGNATURE_FIELDS
    if unknown:
        raise AllowListError(f"{where}: expected has unknown fields {sorted(unknown)}")
    try:
        focus = data.get("focus_rect")
        hashes = data.get("label_hashes")
        return ScreenSignature(
            visible_edits=int(data["visible_edits"]),
            owned_windows=int(data["owned_windows"]),
            focus_class=data.get("focus_class"),
            focus_rect=tuple(int(v) for v in focus) if focus is not None else None,
            paired=int(data["paired"]) if data.get("paired") is not None else None,
            label_hashes=frozenset(str(h) for h in hashes) if hashes is not None else None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AllowListError(f"{where}: expected is malformed: {exc}") from exc


class AllowList:
    """Menu paths explicitly marked read-only, with each step's screen and key."""

    def __init__(self, paths: Iterable[AllowedPath]) -> None:
        self._paths: dict[str, AllowedPath] = {}
        for entry in paths:
            if entry.path in self._paths:
                raise AllowListError(f"path {entry.path!r} is listed twice")
            if not entry.steps:
                raise AllowListError(f"path {entry.path!r} has no steps")
            self._paths[entry.path] = entry

    @classmethod
    def load(cls, path: Path | str) -> "AllowList":
        """Load the private allow-list JSON. Any doubt about it refuses to load."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AllowListError(f"allow-list {path} is unreadable: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("paths"), list):
            raise AllowListError("allow-list must be an object with a list of paths")
        entries = []
        for item in data["paths"]:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise AllowListError("each entry needs a path string")
            name = item["path"]
            steps = item.get("steps")
            if not isinstance(steps, list) or not steps:
                raise AllowListError(f"path {name!r} has no steps")
            parsed = []
            for i, step in enumerate(steps):
                where = f"path {name!r} step {i}"
                if not isinstance(step, dict) or "expected" not in step:
                    raise AllowListError(f"{where}: needs an expected screen")
                key = step.get("key")
                if not isinstance(key, str) or not key:
                    raise AllowListError(f"{where}: needs a key")
                parsed.append(AllowedStep(_signature_from(step["expected"], where), key))
            entries.append(AllowedPath(name, tuple(parsed)))
        return cls(entries)

    def problem(self, path: str, step: int, key: str, observed: ScreenSignature) -> str | None:
        """Why ``key`` may not be sent at ``step`` of ``path``, or None."""
        entry = self._paths.get(path)
        if entry is None:
            return f"menu path {path!r} is not on the allow-list"
        if not 0 <= step < len(entry.steps):
            return f"path {path!r} has no step {step}"
        allowed = entry.steps[step]
        if key != allowed.key:
            return f"step {step} of {path!r} allows only {allowed.key!r}, not {key!r}"
        mismatch = signature_problem(allowed.expected, observed)
        if mismatch is not None:
            return f"the screen does not match step {step} of {path!r}: {mismatch}"
        return None


@dataclass(frozen=True)
class ForegroundObservation:
    """Who is in front, and who owns the topmost window at the target point.
    Instances are (pid, process start time)."""

    foreground_instance: tuple[int, int]
    foreground_image: str
    topmost_instance: tuple[int, int]
    topmost_image: str


def foreground_problem(bound: tuple[int, int], observed: ForegroundObservation) -> str | None:
    """Why the bound instance is not safely in front at the point, or None."""
    checks = (
        (observed.foreground_instance, observed.foreground_image, "is the foreground window"),
        (observed.topmost_instance, observed.topmost_image, "covers the target point"),
    )
    for instance, image, what in checks:
        if instance == bound:
            continue
        if instance[0] == bound[0]:
            return (
                f"process {instance[0]} {what} but has another start time: "
                "not the bound instance (restarted, or the pid was reused)"
            )
        return f"{image} (pid {instance[0]}) {what}, not the application"
    return None


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


def clipping_problem(tree: WindowNode, hwnd: int) -> str | None:
    """Why the field ``hwnd`` is not fully inside the visible client area of
    every ancestor, or None. Unknown client areas fail closed."""
    path = _path_to(tree, hwnd)
    if path is None:
        return "the target field is not in the window tree"
    field_rect = path[-1].rect
    for ancestor in path[:-1]:
        if ancestor.client_rect is None:
            return "the client area of an ancestor is unknown; cannot verify the field is visible"
        if not _inside(field_rect, ancestor.client_rect):
            return (
                f"the field lies outside the visible client area of its "
                f"{ancestor.class_name} ancestor (scrolled out or clipped)"
            )
    return None


@dataclass(frozen=True)
class OcrBox:
    """A target read by OCR: a rectangle in the frame it was seen in."""

    rect: Rect


def audit_record(target: Win32Field | OcrBox, frame_hash: str) -> dict:
    """What the audit keeps about a target: identity, frame hash and
    rectangles. Never a label, a value or any other text."""
    if isinstance(target, OcrBox):
        return {"kind": "ocr-box", "frame_hash": frame_hash, "rect": list(target.rect)}
    return {
        "kind": "win32-field",
        "frame_hash": frame_hash,
        "process_image": target.process_image,
        "instance": list(target.instance),
        "class_path": list(target.class_path),
        "label_hash": target.label_hash,
        "rect": list(target.rect),
        "label_rect": list(target.label_rect),
        "screen_rect": list(target.screen_rect),
    }


@dataclass(frozen=True)
class BoundKeyRequest:
    """One key for the application, with everything the gate checks it against."""

    action: Action
    path: str
    step: int
    app_instance: tuple[int, int]
    signature: ScreenSignature
    foreground: ForegroundObservation
    target: Win32Field | OcrBox | None = None
    tree: WindowNode | None = None


def bound_key_problem(request: BoundKeyRequest, allow: AllowList) -> str | None:
    """Why the key may not be sent, or None. Checked in this order: the
    action's shape, the foreground, the allow-list and screen, the target."""
    action = request.action
    if action.kind is not ActionKind.KEY:
        return f"bound input accepts only key actions, not {action.kind.value}"
    if len(action.keys) != 1:
        return f"a bound key action sends exactly one key, not {len(action.keys)}"
    problem = foreground_problem(request.app_instance, request.foreground)
    if problem is not None:
        return problem
    problem = allow.problem(request.path, request.step, action.keys[0], request.signature)
    if problem is not None:
        return problem
    target = request.target
    if isinstance(target, Win32Field):
        if target.instance != request.app_instance:
            return "the target field belongs to another process instance"
        if request.tree is None:
            return "a Win32 field target needs the window tree to check it is visible"
        return clipping_problem(request.tree, target.hwnd)
    return None
