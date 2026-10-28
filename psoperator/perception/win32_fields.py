"""Read-only Win32 field identity for the pilot application.

The probe (``docs/windows-probe.md``) found UI Automation too slow to use on
the application, and control ids reallocated on every opening. What held, 64
of 64 across openings and a restart, was this: each ``Edit`` is identified by
the label panel directly to its left, by that panel's internal name (compared
as a hash) and both rectangles. In the recorded layouts every label overlaps
its Edit by 3 px, the two share a vertical centre, and no panel serves two
Edits. The visible labels are painted, so a panel's caption is an internal
name, not displayed text (0 of 64 matched what OCR read beside it).

Text is never part of identity. A panel's caption is hashed as it is read and
only the hash is kept or returned (the plaintext is not stored, though Python
does not securely erase the strings it passed through). An Edit's text is
never read at all.

Two layers:

- :func:`pair_fields` is pure. It takes a recorded window tree
  (:class:`WindowNode`) and returns the fields, so it runs on every platform.
- :func:`read_window_tree` and :func:`scan_window` read a live window with
  ``user32`` calls that send the window no message, in this process or any
  other: class name, rectangle, visibility, and the caption of label-class
  windows (``InternalGetWindowText``, never ``GetWindowText``).

Pairing: for each visible Edit, the label candidates are the visible
label-class windows whose vertical centre is within :data:`ROW_TOLERANCE_PX`
of the Edit's and whose right edge lies from :data:`MAX_GAP_PX` left of the
Edit's left edge to :data:`OVERLAP_PX` past it. The nearest is the label. An
Edit stays **unpaired**, and is counted, when there is no candidate, when two
are equally near, when the nearest has no name, when its panel is also the
nearest for another Edit, or when its identity is not unique. It never falls
back to a farther panel: that would bind the wrong label, and the gatekeeper
admits input against this identity.

Identity (:attr:`Win32Field.identity`) is what holds across openings,
restarts and window moves: its rectangles are relative to the scanned
top-level window, and the screen rectangle is kept apart for acting. The
process instance (:attr:`Win32Field.instance`: pid and process start time,
since Windows reuses pids) is separate, and a binding must match both.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from dataclasses import dataclass, field

LABEL_CLASS = "wxWindowClassNR"
EDIT_CLASS = "Edit"
#: Vertical centres must differ by less than this (pixels).
ROW_TOLERANCE_PX = 8
#: A panel's right edge may sit this far past the Edit's left edge (pixels).
OVERLAP_PX = 4
#: ...and at most this far left of it (pixels).
MAX_GAP_PX = 8
#: A window tree larger, or deeper, than this is refused rather than truncated.
MAX_NODES = 20_000
MAX_DEPTH = 64
#: A caption this long or longer is refused rather than hashed truncated.
MAX_NAME_CHARS = 1023

Rect = tuple[int, int, int, int]  # x, y, width, height in screen pixels


class Win32FieldError(Exception):
    """The window could not be read, or is not one this module will read."""


def name_hash(text: str) -> str:
    """SHA-256 of a window's internal name, the only form in which it is kept."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WindowNode:
    """One window in a recorded tree. ``name_hash`` is set only for
    label-class windows below the root with a non-empty caption; no text is
    stored."""

    class_name: str
    rect: Rect
    visible: bool = True
    name_hash: str | None = None
    hwnd: int = 0
    children: tuple["WindowNode", ...] = ()


@dataclass(frozen=True)
class Win32Field:
    """One Edit. ``identity`` holds across openings, restarts and window
    moves: its rectangles are relative to the scanned top-level window.
    ``instance`` names the running process. ``screen_rect`` and ``hwnd``
    only locate the field now, for acting, and are excluded from equality."""

    pid: int
    process_started: int
    process_image: str
    class_path: tuple[str, ...]
    label_hash: str
    rect: Rect
    label_rect: Rect
    screen_rect: Rect = field(default=(0, 0, 0, 0), compare=False)
    hwnd: int = field(default=0, compare=False)

    @property
    def identity(self) -> tuple:
        return (self.process_image, self.class_path, self.label_hash, self.rect, self.label_rect)

    @property
    def instance(self) -> tuple[int, int]:
        return (self.pid, self.process_started)


@dataclass(frozen=True)
class FieldScan:
    fields: tuple[Win32Field, ...]
    #: Visible Edits not emitted: no candidate, a tie, an unnamed or shared
    #: nearest panel, or a non-unique identity.
    unpaired: int


def _centre_y(rect: Rect) -> float:
    return rect[1] + rect[3] / 2


def _right(rect: Rect) -> int:
    return rect[0] + rect[2]


def _walk(root: WindowNode, *, max_nodes: int, max_depth: int):
    """Visible descendants of ``root`` with their class paths, iteratively,
    in document order. A hidden window hides everything below it."""
    stack = [(child, (root.class_name, child.class_name), 1) for child in reversed(root.children)]
    seen = 0
    while stack:
        node, path, depth = stack.pop()
        seen += 1
        if seen > max_nodes:
            raise Win32FieldError(f"window tree exceeds {max_nodes} windows; refusing to truncate")
        if depth > max_depth:
            raise Win32FieldError(f"window tree deeper than {max_depth}; refusing to truncate")
        if not node.visible:
            continue
        yield node, path
        stack.extend(
            (child, (*path, child.class_name), depth + 1) for child in reversed(node.children)
        )


def pair_fields(
    root: WindowNode,
    *,
    pid: int,
    process_started: int,
    process_image: str,
    label_class: str = LABEL_CLASS,
    edit_class: str = EDIT_CLASS,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
) -> FieldScan:
    """Pair each visible Edit below ``root`` with its label panel. The root is
    the container: it is never itself a field or a label, even when it has the
    label class (the application's top-level window does). Only its
    descendants are candidates, so the root's own name is never used."""
    if root.class_name == edit_class:
        raise Win32FieldError(f"the root must be a container, not {root.class_name!r}")
    edits: list[tuple[WindowNode, tuple[str, ...]]] = []
    panels: list[WindowNode] = []
    if root.visible:
        for node, path in _walk(root, max_nodes=max_nodes, max_depth=max_depth):
            if node.class_name == edit_class:
                edits.append((node, path))
            elif node.class_name == label_class:
                panels.append(node)

    chosen: list[tuple[WindowNode, tuple[str, ...], WindowNode | None]] = []
    for edit, path in edits:
        left = edit.rect[0]
        row = [
            p
            for p in panels
            if abs(_centre_y(p.rect) - _centre_y(edit.rect)) < ROW_TOLERANCE_PX
            and left - MAX_GAP_PX <= _right(p.rect) <= left + OVERLAP_PX
        ]
        label = None
        if row:
            nearest_edge = max(_right(p.rect) for p in row)
            nearest = [p for p in row if _right(p.rect) == nearest_edge]
            if len(nearest) == 1 and nearest[0].name_hash is not None:
                label = nearest[0]
        chosen.append((edit, path, label))

    uses = Counter(id(label) for _, _, label in chosen if label is not None)
    origin_x, origin_y = root.rect[0], root.rect[1]

    def relative(rect: Rect) -> Rect:
        return (rect[0] - origin_x, rect[1] - origin_y, rect[2], rect[3])

    candidates = [
        Win32Field(
            pid=pid,
            process_started=process_started,
            process_image=process_image,
            class_path=path,
            label_hash=label.name_hash,
            rect=relative(edit.rect),
            label_rect=relative(label.rect),
            screen_rect=edit.rect,
            hwnd=edit.hwnd,
        )
        for edit, path, label in chosen
        if label is not None and uses[id(label)] == 1
    ]
    # Belt and braces: equal rectangles always tie, and a shared panel is
    # refused above, so two candidates cannot share an identity today. This
    # keeps it true if those rules change.
    identities = Counter(f.identity for f in candidates)
    fields = sorted(
        (f for f in candidates if identities[f.identity] == 1),
        key=lambda f: (f.rect[1], f.rect[0]),
    )
    return FieldScan(tuple(fields), len(edits) - len(fields))


# --- reading a live window (Windows) -------------------------------------------
# Every call here reads state the window manager already holds; none sends the
# window a message. (GetWindowText and GetWindowTextLength would, for a window
# of this process, so they are not used.)

_GW_HWNDNEXT = 2
_GW_CHILD = 5
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _user32():
    import ctypes
    from ctypes import wintypes

    if os.name != "nt":
        raise Win32FieldError("reading Win32 windows is only available on Windows")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.IsWindow.argtypes = [wintypes.HWND]
    user32.IsWindow.restype = wintypes.BOOL
    user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetWindow.restype = wintypes.HWND
    user32.InternalGetWindowText.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.InternalGetWindowText.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    return user32


def _class_name(user32, hwnd: int) -> str:
    import ctypes

    buffer = ctypes.create_unicode_buffer(256)
    if not user32.GetClassNameW(hwnd, buffer, 256):
        raise Win32FieldError("GetClassNameW failed")
    return buffer.value


def _rect(user32, hwnd: int) -> Rect:
    import ctypes
    from ctypes import wintypes

    r = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(r)):
        raise Win32FieldError("GetWindowRect failed")
    return (r.left, r.top, r.right - r.left, r.bottom - r.top)


def _label_name_hash(user32, hwnd: int) -> str | None:
    """Hash a label window's caption, read with InternalGetWindowText, which
    copies the caption the window manager stores and sends no message."""
    import ctypes

    size = MAX_NAME_CHARS + 1
    buffer = ctypes.create_unicode_buffer(size)
    copied = user32.InternalGetWindowText(hwnd, buffer, size)
    if copied >= MAX_NAME_CHARS:
        raise Win32FieldError(f"a label caption of {MAX_NAME_CHARS}+ characters; refusing it")
    digest = name_hash(buffer.value[:copied]) if copied > 0 else None
    ctypes.memset(buffer, 0, ctypes.sizeof(buffer))
    return digest


def read_window_tree(
    hwnd: int,
    *,
    label_class: str = LABEL_CLASS,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
) -> WindowNode:
    """Record the tree under ``hwnd``: class, rectangle and visibility of every
    window, and the hashed caption of label-class windows below the root."""
    user32 = _user32()
    if not user32.IsWindow(hwnd):
        raise Win32FieldError("not a window")
    count = 0

    def node_of(handle: int, depth: int, children: tuple) -> WindowNode:
        class_name = _class_name(user32, handle)
        named = depth > 0 and class_name == label_class
        return WindowNode(
            class_name=class_name,
            rect=_rect(user32, handle),
            visible=bool(user32.IsWindowVisible(handle)),
            name_hash=_label_name_hash(user32, handle) if named else None,
            hwnd=int(handle),
            children=children,
        )

    # Post-order, iteratively: a node is built once all its children are.
    stack: list[tuple[int, int, list | None]] = [(hwnd, 0, None)]
    built: dict[int, WindowNode] = {}
    while stack:
        handle, depth, kids = stack.pop()
        if kids is None:
            count += 1
            if count > max_nodes:
                raise Win32FieldError(
                    f"window tree exceeds {max_nodes} windows; refusing to truncate"
                )
            if depth > max_depth:
                raise Win32FieldError(f"window tree deeper than {max_depth}; refusing to truncate")
            kids = []
            child = user32.GetWindow(handle, _GW_CHILD)
            while child:
                kids.append(int(child))
                child = user32.GetWindow(child, _GW_HWNDNEXT)
            stack.append((handle, depth, kids))
            stack.extend((k, depth + 1, None) for k in reversed(kids))
        else:
            built[handle] = node_of(handle, depth, tuple(built.pop(k) for k in kids))
    return built[hwnd]


def process_of(hwnd: int) -> tuple[int, int, str]:
    """The pid, start time (FILETIME, 100 ns units) and image file name (no
    directory) of the process owning ``hwnd``."""
    import ctypes
    from ctypes import wintypes

    user32 = _user32()
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        raise Win32FieldError("no process owns this window")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    process = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not process:
        raise Win32FieldError(f"cannot open process {pid.value}")
    try:
        size = wintypes.DWORD(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(process, 0, buffer, ctypes.byref(size)):
            raise Win32FieldError(f"cannot read the image name of process {pid.value}")
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(process, *(ctypes.byref(t) for t in times)):
            raise Win32FieldError(f"cannot read the start time of process {pid.value}")
        started = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        return pid.value, started, os.path.basename(buffer.value[: size.value])
    finally:
        kernel32.CloseHandle(process)


def scan_window(hwnd: int, *, label_class: str = LABEL_CLASS) -> FieldScan:
    """Read ``hwnd`` and return its fields. Read-only: no message, no focus."""
    pid, started, image = process_of(hwnd)
    tree = read_window_tree(hwnd, label_class=label_class)
    return pair_fields(
        tree, pid=pid, process_started=started, process_image=image, label_class=label_class
    )
