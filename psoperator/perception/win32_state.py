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

import functools
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
# when this thread's desktop is not the active desktop, when the input
# desktop does not allow this process the hook or journal-record right, and
# when UIPI keeps this process from the foreground thread (a foreground
# process of higher integrity). Before the zeros may be read as "not held",
# each check (_keyboard_readable) establishes: the session is connected and
# unlocked (in a disconnected session OpenInputDesktop still succeeds, with
# the desktop that becomes active on reconnection); this process is in the
# interactive window station, where the input desktop opens with those
# rights and is this thread's desktop; and the foreground process's
# integrity level is known and not above this process's.
_DESKTOP_READ = 0x0001 | 0x0008 | 0x0010  # read objects, hook control, journal record
_UOI_FLAGS, _UOI_NAME = 1, 2
_WSF_VISIBLE = 0x0001
_INTERACTIVE_STATION = "WinSta0"
_WTS_CURRENT_SESSION = 0xFFFFFFFF
_WTS_SESSION_INFO_EX = 25
_WTS_ACTIVE, _WTS_SESSIONSTATE_UNLOCK = 0, 1
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008
_TOKEN_INTEGRITY_LEVEL = 25


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
    user32.GetProcessWindowStation.argtypes = []
    user32.GetProcessWindowStation.restype = wintypes.HANDLE
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


@functools.cache
def _security_api():
    import ctypes
    from ctypes import wintypes

    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    wtsapi32.WTSQuerySessionInformationW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    wtsapi32.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    wtsapi32.WTSFreeMemory.restype = None
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi32.IsValidSid.restype = wintypes.BOOL
    advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    class Level1(ctypes.Structure):  # WTSINFOEX_LEVEL1_W
        _fields_ = [
            ("SessionId", wintypes.ULONG),
            ("SessionState", ctypes.c_int),
            ("SessionFlags", wintypes.LONG),
            ("WinStationName", wintypes.WCHAR * 33),
            ("UserName", wintypes.WCHAR * 21),
            ("DomainName", wintypes.WCHAR * 18),
            ("LogonTime", ctypes.c_longlong),
            ("ConnectTime", ctypes.c_longlong),
            ("DisconnectTime", ctypes.c_longlong),
            ("LastInputTime", ctypes.c_longlong),
            ("CurrentTime", ctypes.c_longlong),
            ("Counters", wintypes.DWORD * 6),
        ]

    class Data(ctypes.Union):
        _fields_ = [("WTSInfoExLevel1", Level1)]

    class InfoEx(ctypes.Structure):  # WTSINFOEXW
        _fields_ = [("Level", wintypes.DWORD), ("Data", Data)]

    return wtsapi32, advapi32, kernel32, InfoEx


def session_ok(level: object, state: object, flags: object) -> bool:
    """Whether a WTSINFOEX reading shows a connected (active), unlocked
    session: level 1, state WTSActive, flags WTS_SESSIONSTATE_UNLOCK."""
    return (
        type(level) is int
        and level == 1
        and type(state) is int
        and state == _WTS_ACTIVE
        and type(flags) is int
        and flags == _WTS_SESSIONSTATE_UNLOCK
    )


def _session_unlocked() -> bool:
    """Whether this process's session is connected and unlocked; False if
    it cannot be read. Only the state and flags are read from the reply."""
    import ctypes
    from ctypes import wintypes

    try:
        wtsapi32, _, _, info_type = _security_api()
        buffer, size = ctypes.c_void_p(), wintypes.DWORD()
        if not wtsapi32.WTSQuerySessionInformationW(
            None,
            _WTS_CURRENT_SESSION,
            _WTS_SESSION_INFO_EX,
            ctypes.byref(buffer),
            ctypes.byref(size),
        ):
            return False
        try:
            if not buffer.value or size.value < ctypes.sizeof(info_type):
                return False
            info = ctypes.cast(buffer, ctypes.POINTER(info_type)).contents
            level1 = info.Data.WTSInfoExLevel1
            return session_ok(int(info.Level), int(level1.SessionState), int(level1.SessionFlags))
        finally:
            wtsapi32.WTSFreeMemory(buffer)
    except Exception:
        return False


def _integrity(pid: int | None) -> int:
    """The mandatory integrity level (the RID, e.g. 0x2000 medium, 0x3000
    high) of process ``pid``, or of this process for None. Raises if it
    cannot be read."""
    import ctypes
    from ctypes import wintypes

    _, advapi32, kernel32, _ = _security_api()
    if pid is None:
        process, opened = kernel32.GetCurrentProcess(), False
    else:
        process = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            raise OSError("cannot open the process")
        opened = True
    try:
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
            raise OSError("cannot open the process token")
        try:
            needed = wintypes.DWORD()
            advapi32.GetTokenInformation(
                token, _TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(needed)
            )
            if not needed.value:
                raise OSError("cannot size the integrity level")
            label = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(
                token, _TOKEN_INTEGRITY_LEVEL, label, needed, ctypes.byref(needed)
            ):
                raise OSError("cannot read the integrity level")
            sid = ctypes.cast(label, ctypes.POINTER(ctypes.c_void_p))[0]
            if not sid or not advapi32.IsValidSid(sid):
                raise OSError("the integrity label has no valid SID")
            count = advapi32.GetSidSubAuthorityCount(sid)[0]
            if count < 1:
                raise OSError("the integrity SID has no sub-authority")
            return int(advapi32.GetSidSubAuthority(sid, count - 1)[0])
        finally:
            kernel32.CloseHandle(token)
    finally:
        if opened:
            kernel32.CloseHandle(process)


def _foreground_pid(user32) -> int:
    import ctypes
    from ctypes import wintypes

    foreground = user32.GetForegroundWindow()
    pid = wintypes.DWORD()
    if foreground:
        user32.GetWindowThreadProcessId(foreground, ctypes.byref(pid))
    return int(pid.value)


def _privilege_verified(user32) -> None:
    """Raise ``privilege-not-verified`` unless the foreground process's
    integrity level is known and not above this process's (UIPI)."""
    try:
        pid = _foreground_pid(user32)
        verified = bool(pid) and _integrity(pid) <= _integrity(None)
    except Exception:
        verified = False
    if not verified:
        raise KeyStateRefusal(Code.PRIVILEGE_UNVERIFIED)


def _object_name(user32, handle) -> str:
    import ctypes
    from ctypes import wintypes

    buffer = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD()
    if not user32.GetUserObjectInformationW(
        handle, _UOI_NAME, buffer, ctypes.sizeof(buffer), ctypes.byref(needed)
    ):
        raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    return buffer.value


def _interactive_station(user32) -> bool:
    """Whether this process's window station is the visible interactive one
    (WinSta0), the station the input desktop belongs to: a thread's desktop
    belongs to its process's station, so equal names name one desktop."""
    import ctypes
    from ctypes import wintypes

    class Flags(ctypes.Structure):  # USEROBJECTFLAGS
        _fields_ = [
            ("fInherit", wintypes.BOOL),
            ("fReserved", wintypes.BOOL),
            ("dwFlags", wintypes.DWORD),
        ]

    station = user32.GetProcessWindowStation()
    if not station or _object_name(user32, station) != _INTERACTIVE_STATION:
        return False
    flags, needed = Flags(), wintypes.DWORD()
    if not user32.GetUserObjectInformationW(
        station, _UOI_FLAGS, ctypes.byref(flags), ctypes.sizeof(flags), ctypes.byref(needed)
    ):
        return False
    return bool(flags.dwFlags & _WSF_VISIBLE)


def _input_desktop_ours(user32) -> None:
    """Raise ``keyboard-unreadable`` unless this process is in the
    interactive window station and the input desktop opens with the rights
    GetAsyncKeyState needs and is this thread's desktop."""
    if not _interactive_station(user32):
        raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    desktop = user32.OpenInputDesktop(0, False, _DESKTOP_READ)
    if not desktop:
        raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    try:
        ours = user32.GetThreadDesktop(threading.get_native_id())
        name = _object_name(user32, desktop)
        if not ours or not name or _object_name(user32, ours) != name:
            raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    finally:
        user32.CloseDesktop(desktop)


def _keyboard_readable(user32) -> None:
    """Raise :class:`KeyStateRefusal` unless GetAsyncKeyState can read the
    keyboard now: ``keyboard-unreadable`` for a disconnected or locked
    session or another desktop, ``privilege-not-verified`` for a foreground
    process of higher or unknown integrity."""
    if not _session_unlocked():
        raise KeyStateRefusal(Code.KEYBOARD_UNREADABLE)
    _input_desktop_ours(user32)
    _privilege_verified(user32)


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
