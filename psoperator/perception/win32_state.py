"""Live, read-only observations for the bound-target gate.

:func:`observe` reports what the gate checks before a key: the foreground
window, the control with keyboard focus and whether a menu, move/size or
mouse-capture mode is active in the main window's thread, whether a Shift,
Ctrl, Alt or Windows key is held (refused with its own code, as is a keyboard
whose state this desktop cannot read), the top-level window
at the centre of the focused control, the visible windows owned by the main
window (dialogs), and the main window's tree and screen signature. The window
state is read before and after the (slower) tree walk; if it changed in
between, no observation is returned. Every call reads state the window manager
already holds; none sends a window a message or changes focus.
"""

from __future__ import annotations

import threading
import time

from psoperator.gatekeeper.bound_target import (
    Code,
    KeyStateRefusal,
    Observation,
    signature_of,
)
from psoperator.perception.win32_fields import (
    LABEL_CLASS,
    Win32FieldError,
    process_of,
    read_window_tree,
    user32_api,
)

_GA_ROOT = 2
_GW_OWNER = 4
# GUITHREADINFO flags: move/size, menu, system-menu and popup-menu modes.
_INTERCEPTING = 0x2 | 0x4 | 0x8 | 0x10
# Shift, Ctrl, Alt (generic, left and right) and both Windows keys. SendInput
# keeps the existing keyboard state, so a held one turns ENTER into a chord.
_MODIFIER_VKS = (0x10, 0x11, 0x12, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x5B, 0x5C)
_KEY_DOWN = 0x8000
# GetAsyncKeyState returns 0 ("not down") when it cannot read the keyboard:
# when this thread's desktop is not the input desktop (a locked workstation,
# the secure desktop, a disconnected remote session), or when the input
# desktop does not allow this process the hook or journal-record right.
# Opening the input desktop with those rights and finding it is this thread's
# desktop rules both out, so the zeros may be read as "not held".
_DESKTOP_READ = 0x0001 | 0x0008 | 0x0010  # read objects, hook control, journal record
_UOI_NAME = 2


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
    user32.EnumWindows.restype = wintypes.BOOL
    user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user32.GetAsyncKeyState.restype = ctypes.c_short
    user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    user32.OpenInputDesktop.restype = wintypes.HANDLE
    user32.GetThreadDesktop.argtypes = [wintypes.DWORD]
    user32.GetThreadDesktop.restype = wintypes.HANDLE
    user32.GetUserObjectInformationW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    user32.GetUserObjectInformationW.restype = wintypes.BOOL
    user32.CloseDesktop.argtypes = [wintypes.HANDLE]
    user32.CloseDesktop.restype = wintypes.BOOL
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


def _thread_state(user32, info_type, hwnd: int) -> tuple[int, bool]:
    """The focused control of ``hwnd``'s thread, and whether no menu,
    move/size or capture mode is active there."""
    import ctypes

    info = info_type(cbSize=ctypes.sizeof(info_type))
    thread = user32.GetWindowThreadProcessId(hwnd, None)
    if not thread or not user32.GetGUIThreadInfo(thread, ctypes.byref(info)):
        raise Win32FieldError("cannot read the main window's thread state")
    clear = (
        not info.flags & _INTERCEPTING
        and not info.hwndCapture
        and not info.hwndMenuOwner
        and not info.hwndMoveSize
    )
    return int(info.hwndFocus or 0), clear


def _owned_visible(user32, hwnd: int) -> int:
    import ctypes
    from ctypes import wintypes

    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(h, _):
        if user32.IsWindowVisible(h) and user32.GetWindow(h, _GW_OWNER) == hwnd:
            found.append(h)
        return True

    # The callback never stops the enumeration, so a zero return is a failure:
    # it must not pass for "no dialogs" (and two failures must not agree).
    if not user32.EnumWindows(visit, 0):
        raise Win32FieldError("cannot enumerate the top-level windows")
    return len(found)


def _centre(user32, hwnd: int) -> tuple[int, int]:
    import ctypes
    from ctypes import wintypes

    r = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(r)):
        raise Win32FieldError("cannot read the focused control's rectangle")
    return ((r.left + r.right) // 2, (r.top + r.bottom) // 2)


def _desktop_name(user32, desktop) -> str:
    import ctypes
    from ctypes import wintypes

    buffer = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD()
    if not user32.GetUserObjectInformationW(
        desktop, _UOI_NAME, buffer, ctypes.sizeof(buffer), ctypes.byref(needed)
    ):
        raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    return buffer.value


def _keyboard_readable(user32) -> None:
    """Raise ``keyboard-unreadable`` unless the input desktop opens with the
    rights GetAsyncKeyState needs and is this thread's desktop."""
    desktop = user32.OpenInputDesktop(0, False, _DESKTOP_READ)
    if not desktop:
        raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    try:
        ours = user32.GetThreadDesktop(threading.get_native_id())
        name = _desktop_name(user32, desktop)
        if not ours or not name or _desktop_name(user32, ours) != name:
            raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    finally:
        user32.CloseDesktop(desktop)


def _modifiers_clear(user32) -> bool:
    """Whether no Shift, Ctrl, Alt or Windows key is down (physical state)."""
    return not any(int(user32.GetAsyncKeyState(vk)) & _KEY_DOWN for vk in _MODIFIER_VKS)


def _modifiers_sampled(user32) -> None:
    """Sample the modifiers, between two checks that the keyboard is
    readable: ``keyboard-unreadable`` or ``modifier-held`` if not clear."""
    _keyboard_readable(user32)
    if not _modifiers_clear(user32):
        raise KeyStateRefusal(Code.MODIFIER_HELD)
    _keyboard_readable(user32)


def _recipient(user32, info_type, main_hwnd: int) -> tuple:
    """Who would receive a key now, and as what: the foreground window, the
    focused control, whether no menu/move-size/capture mode is active, the
    focused control's centre, the top-level window there, and whether no
    modifier key is held (always True: a held modifier, or a keyboard whose
    state cannot be read, raises :class:`KeyStateRefusal` with its code)."""
    # The modifiers are sampled first and last, so a modifier down at the
    # start or the end of the reading refuses with its own code.
    _modifiers_sampled(user32)
    thread = _thread_state(user32, info_type, main_hwnd)
    foreground = int(user32.GetForegroundWindow() or 0)
    focus, clear = thread
    if not focus:
        raise Win32FieldError("the main window's thread has no keyboard focus")
    point = _centre(user32, focus)
    top = topmost_at(point)
    # Focus, input modes and the foreground are sampled again after the other
    # reads, the foreground on both sides of the thread state: a change in
    # between is an inconsistent recipient.
    if (
        int(user32.GetForegroundWindow() or 0) != foreground
        or _thread_state(user32, info_type, main_hwnd) != thread
        or int(user32.GetForegroundWindow() or 0) != foreground
    ):
        raise Win32FieldError("the recipient changed while it was being read")
    # Samples, not a lock: a modifier pressed and released between the two
    # samples, or pressed after the last poll of its key, is not seen.
    _modifiers_sampled(user32)
    return (foreground, focus, clear, point, top, True)


def recipient(main_hwnd: int) -> tuple:
    """Who would receive a key now, read alone (fast): the gate reads this
    immediately before and after handing a key to the executor. Raises if the
    window is gone or the reading is inconsistent."""
    user32, info_type = _api()
    if not user32.IsWindow(main_hwnd):
        raise Win32FieldError("the main window no longer exists")
    return _recipient(user32, info_type, main_hwnd)


def observe(main_hwnd: int, *, label_class: str = LABEL_CLASS) -> Observation:
    """Observe the main window ``main_hwnd`` for a key to its focused control.

    The slow work (enumerating dialogs, walking the tree) runs between two
    readings of the recipient state, and the second reading is the last thing
    done: if the recipient, the dialogs or the process changed at any point,
    no observation is returned. Raises if the window is gone."""
    user32, info_type = _api()
    if not user32.IsWindow(main_hwnd):
        raise Win32FieldError("the main window no longer exists")
    at = time.monotonic()
    pid, started, image = process_of(main_hwnd)
    first = _recipient(user32, info_type, main_hwnd)
    owned = _owned_visible(user32, main_hwnd)
    tree = read_window_tree(main_hwnd, label_class=label_class)
    foreground, focus, clear, point, top, modifiers = first
    signature = signature_of(
        tree, focus, owned, instance=(pid, started), image=image, label_class=label_class
    )
    if _owned_visible(user32, main_hwnd) != owned:
        raise Win32FieldError("the dialogs changed during observation")
    if process_of(main_hwnd)[:2] != (pid, started):
        raise Win32FieldError("the main window's process changed during observation")
    # Last: the recipient state, read after all other work.
    if _recipient(user32, info_type, main_hwnd) != first:
        raise Win32FieldError("the recipient changed during observation")
    return Observation(
        at=at,
        main_hwnd=int(main_hwnd),
        instance=(pid, started),
        image=image,
        foreground_hwnd=foreground,
        topmost_hwnd=top,
        focus_hwnd=focus,
        input_clear=clear,
        modifiers_clear=modifiers,
        point=point,
        signature=signature,
        tree=tree,
    )
