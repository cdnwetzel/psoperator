"""Live, read-only observations for the bound-target gate.

:func:`observe` reports what the gate checks before a key: the foreground
window, the top-level window at the target point, the control with keyboard
focus, the visible windows owned by the main window (dialogs), and the main
window's tree and screen signature. Every call reads state the window manager
already holds; none sends a window a message or changes focus.
"""

from __future__ import annotations

import time

from psoperator.gatekeeper.bound_target import Observation, signature_of
from psoperator.perception.win32_fields import (
    LABEL_CLASS,
    Win32FieldError,
    process_of,
    read_window_tree,
    user32_api,
)

_GA_ROOT = 2
_GW_OWNER = 4


def _api():
    import ctypes
    from ctypes import wintypes

    user32 = user32_api()
    user32.GetForegroundWindow.argtypes = []
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.WindowFromPoint.argtypes = [wintypes.POINT]
    user32.WindowFromPoint.restype = wintypes.HWND
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND

    class GUITHREADINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("flags", wintypes.DWORD),
            ("hwndActive", wintypes.HWND),
            ("hwndFocus", wintypes.HWND),
            ("hwndCapture", wintypes.HWND),
            ("hwndMenuOwner", wintypes.HWND),
            ("hwndMoveSize", wintypes.HWND),
            ("hwndCaret", wintypes.HWND),
            ("rcCaret", wintypes.RECT),
        ]

    user32.GetGUIThreadInfo.argtypes = [wintypes.DWORD, ctypes.POINTER(GUITHREADINFO)]
    user32.GetGUIThreadInfo.restype = wintypes.BOOL
    user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
    return user32, GUITHREADINFO


def topmost_at(point: tuple[int, int]) -> int:
    """The top-level window at screen ``point`` (an owned popup is its own
    top-level window). Raises if there is none."""
    from ctypes import wintypes

    user32, _ = _api()
    at = user32.WindowFromPoint(wintypes.POINT(*point))
    top = user32.GetAncestor(at, _GA_ROOT) if at else None
    if not top:
        raise Win32FieldError(f"no window at {point}")
    return int(top)


def _focus_of(user32, info_type, hwnd: int) -> int:
    import ctypes

    info = info_type(cbSize=ctypes.sizeof(info_type))
    thread = user32.GetWindowThreadProcessId(hwnd, None)
    if not thread or not user32.GetGUIThreadInfo(thread, ctypes.byref(info)):
        raise Win32FieldError("cannot read the main window's keyboard focus")
    return int(info.hwndFocus or 0)


def _owned_visible(user32, hwnd: int) -> int:
    import ctypes
    from ctypes import wintypes

    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(h, _):
        if user32.IsWindowVisible(h) and user32.GetWindow(h, _GW_OWNER) == hwnd:
            found.append(h)
        return True

    user32.EnumWindows(visit, 0)
    return len(found)


def observe(
    main_hwnd: int, point: tuple[int, int], *, label_class: str = LABEL_CLASS
) -> Observation:
    """Observe the main window ``main_hwnd`` for a key aimed at ``point``."""
    user32, info_type = _api()
    if not user32.IsWindow(main_hwnd):
        raise Win32FieldError("the main window no longer exists")
    at = time.monotonic()
    pid, started, image = process_of(main_hwnd)
    foreground = int(user32.GetForegroundWindow() or 0)
    top = topmost_at(point)
    focus = _focus_of(user32, info_type, main_hwnd)
    owned = _owned_visible(user32, main_hwnd)
    tree = read_window_tree(main_hwnd, label_class=label_class)
    signature = signature_of(
        tree,
        focus,
        owned,
        pid=pid,
        process_started=started,
        process_image=image,
        label_class=label_class,
    )
    return Observation(
        at=at,
        main_hwnd=int(main_hwnd),
        instance=(pid, started),
        foreground_hwnd=foreground,
        topmost_hwnd=top,
        focus_hwnd=focus,
        point=point,
        signature=signature,
        tree=tree,
    )
