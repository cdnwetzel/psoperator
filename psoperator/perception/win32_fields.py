"""Read-only Win32 field identity for the pilot application.

The probe (``docs/windows-probe.md``) found UI Automation too slow to use on
the application, and control ids reallocated on every opening. What held, 64
of 64 across openings and a restart, was this: each ``Edit`` is identified by
the label panel directly to its left, by that panel's internal name (compared
as a hash) and both rectangles. The visible labels are painted, and Win32
returns no field values, so text is never part of identity: the panel's name
is hashed as it is read and the text is dropped, and an Edit's text is never
read at all.

Two layers:

- :func:`pair_fields` is pure. It takes a recorded window tree
  (:class:`WindowNode`) and returns the fields, so it runs on every platform.
- :func:`read_window_tree` and :func:`scan_window` read a live window with
  ``user32``: class names, rectangles, visibility, and the internal name of
  label-class windows only. Nothing is sent to the window that could change
  it, and nothing takes focus.

Pairing (the probe's rule): for each visible Edit, the label candidates are
the visible label-class windows whose vertical centre is within
:data:`ROW_TOLERANCE_PX` of the Edit's and whose right edge is at most
:data:`OVERLAP_PX` past the Edit's left edge; the nearest such panel (the
largest right edge) is the label. A tie, or a nearest panel with no name,
leaves the Edit unpaired rather than falling back to a farther panel, which
would bind the wrong label. Unpaired Edits are counted, not dropped silently.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

LABEL_CLASS = "wxWindowClassNR"
EDIT_CLASS = "Edit"
#: Vertical centres must differ by less than this (pixels).
ROW_TOLERANCE_PX = 8
#: A panel's right edge may sit this far past the Edit's left edge (pixels).
OVERLAP_PX = 4
#: A window tree larger than this is refused rather than truncated.
MAX_NODES = 20_000

Rect = tuple[int, int, int, int]  # x, y, width, height in screen pixels


class Win32FieldError(Exception):
    """The window could not be read, or is not one this module will read."""


def name_hash(text: str) -> str:
    """SHA-256 of a window's internal name, the only form in which it is kept."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WindowNode:
    """One window in a recorded tree. ``name_hash`` is set only for
    label-class windows with a non-empty internal name; no text is stored."""

    class_name: str
    rect: Rect
    visible: bool = True
    name_hash: str | None = None
    hwnd: int = 0
    children: tuple["WindowNode", ...] = ()


@dataclass(frozen=True)
class Win32Field:
    """An Edit's identity. ``hwnd`` locates it now but is not identity (it
    changes on every opening), so it is excluded from equality."""

    pid: int
    process_image: str
    class_path: tuple[str, ...]
    label_hash: str
    rect: Rect
    label_rect: Rect
    hwnd: int = field(default=0, compare=False)

    @property
    def identity(self) -> tuple:
        return (self.process_image, self.class_path, self.label_hash, self.rect, self.label_rect)


@dataclass(frozen=True)
class FieldScan:
    fields: tuple[Win32Field, ...]
    #: Visible Edits with no unambiguous, named label panel.
    unpaired: int


def _centre_y(rect: Rect) -> float:
    return rect[1] + rect[3] / 2


def pair_fields(
    root: WindowNode,
    *,
    pid: int,
    process_image: str,
    label_class: str = LABEL_CLASS,
    edit_class: str = EDIT_CLASS,
) -> FieldScan:
    """Pair each visible Edit under ``root`` with its label panel."""
    edits: list[tuple[WindowNode, tuple[str, ...]]] = []
    panels: list[WindowNode] = []

    def visit(node: WindowNode, path: tuple[str, ...]) -> None:
        for child in node.children:
            if not child.visible:
                continue  # a hidden window hides everything below it
            child_path = (*path, child.class_name)
            if child.class_name == edit_class:
                edits.append((child, child_path))
            elif child.class_name == label_class:
                panels.append(child)
            visit(child, child_path)

    if root.visible:
        visit(root, (root.class_name,))

    fields: list[Win32Field] = []
    unpaired = 0
    for edit, path in edits:
        row = [
            p
            for p in panels
            if abs(_centre_y(p.rect) - _centre_y(edit.rect)) < ROW_TOLERANCE_PX
            and p.rect[0] + p.rect[2] <= edit.rect[0] + OVERLAP_PX
        ]
        if not row:
            unpaired += 1
            continue
        nearest_edge = max(p.rect[0] + p.rect[2] for p in row)
        nearest = [p for p in row if p.rect[0] + p.rect[2] == nearest_edge]
        if len(nearest) != 1 or nearest[0].name_hash is None:
            unpaired += 1
            continue
        label = nearest[0]
        fields.append(
            Win32Field(
                pid=pid,
                process_image=process_image,
                class_path=path,
                label_hash=label.name_hash,
                rect=edit.rect,
                label_rect=label.rect,
                hwnd=edit.hwnd,
            )
        )
    fields.sort(key=lambda f: (f.rect[1], f.rect[0]))
    return FieldScan(tuple(fields), unpaired)


# --- reading a live window (Windows) -------------------------------------------

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
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
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
    """Hash a label window's internal name and drop the text. For a window of
    another process GetWindowTextW reads the stored caption without sending
    the window a message."""
    import ctypes

    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return None
    buffer = ctypes.create_unicode_buffer(length + 1)
    copied = user32.GetWindowTextW(hwnd, buffer, length + 1)
    text = buffer.value[:copied]
    ctypes.memset(buffer, 0, ctypes.sizeof(buffer))
    return name_hash(text) if text else None


def read_window_tree(
    hwnd: int, *, label_class: str = LABEL_CLASS, max_nodes: int = MAX_NODES
) -> WindowNode:
    """Record the tree under ``hwnd``: class, rectangle and visibility of every
    window, and the hashed internal name of label-class windows only."""
    user32 = _user32()
    if not user32.IsWindow(hwnd):
        raise Win32FieldError("not a window")
    count = 0

    def record(handle: int) -> WindowNode:
        nonlocal count
        count += 1
        if count > max_nodes:
            raise Win32FieldError(f"window tree exceeds {max_nodes} windows; refusing to truncate")
        class_name = _class_name(user32, handle)
        children = []
        child = user32.GetWindow(handle, _GW_CHILD)
        while child:
            children.append(record(child))
            child = user32.GetWindow(child, _GW_HWNDNEXT)
        return WindowNode(
            class_name=class_name,
            rect=_rect(user32, handle),
            visible=bool(user32.IsWindowVisible(handle)),
            name_hash=_label_name_hash(user32, handle) if class_name == label_class else None,
            hwnd=int(handle),
            children=tuple(children),
        )

    return record(hwnd)


def process_of(hwnd: int) -> tuple[int, str]:
    """The pid and image file name (no directory) of the process owning ``hwnd``."""
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
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    process = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not process:
        raise Win32FieldError(f"cannot open process {pid.value}")
    try:
        size = wintypes.DWORD(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(process, 0, buffer, ctypes.byref(size)):
            raise Win32FieldError(f"cannot read the image name of process {pid.value}")
        return pid.value, os.path.basename(buffer.value[: size.value])
    finally:
        kernel32.CloseHandle(process)


def scan_window(hwnd: int, *, label_class: str = LABEL_CLASS) -> FieldScan:
    """Read ``hwnd`` and return its fields. Read-only: no input, no focus."""
    pid, image = process_of(hwnd)
    tree = read_window_tree(hwnd, label_class=label_class)
    return pair_fields(tree, pid=pid, process_image=image, label_class=label_class)
