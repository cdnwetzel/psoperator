"""Live, read-only observations the bound-target gate checks before a key.

Who owns the foreground window, and who owns the topmost window at the target
point, each as a process instance (pid and start time) with its image name.
Every call reads state the window manager already holds; none sends a window a
message or changes focus.
"""

from __future__ import annotations

from psoperator.gatekeeper.bound_target import ForegroundObservation
from psoperator.perception.win32_fields import Win32FieldError, _user32, process_of

_GA_ROOT = 2


def observe_foreground(point: tuple[int, int]) -> ForegroundObservation:
    """The foreground window's process, and the process owning the topmost
    top-level window at screen ``point``. Raises if either cannot be read."""
    import ctypes
    from ctypes import wintypes

    user32 = _user32()
    user32.GetForegroundWindow.argtypes = []
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.WindowFromPoint.argtypes = [wintypes.POINT]
    user32.WindowFromPoint.restype = wintypes.HWND
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND

    foreground = user32.GetForegroundWindow()
    if not foreground:
        raise Win32FieldError("no foreground window")
    at_point = user32.WindowFromPoint(wintypes.POINT(*point))
    top = user32.GetAncestor(at_point, _GA_ROOT) if at_point else None
    if not top:
        raise Win32FieldError(f"no window at {point}")
    fg_pid, fg_started, fg_image = process_of(foreground)
    top_pid, top_started, top_image = process_of(top)
    del ctypes
    return ForegroundObservation(
        foreground_instance=(fg_pid, fg_started),
        foreground_image=fg_image,
        topmost_instance=(top_pid, top_started),
        topmost_image=top_image,
    )
