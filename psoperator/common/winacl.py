"""Windows owner-only verification through the file's security descriptor (D-01).

POSIX code proves a secret is private with ``fstat``: owner uid and mode
``0600``. Windows has no mode bits; who can read a file is its DACL. This
module is the Windows counterpart. It reads the owner and DACL from an *open
handle*, never from a path checked first and opened later, and it creates
files and directories with an explicit, protected DACL so nothing is
inherited from the parent.

The policy is :func:`owner_only_problem`, a pure function over the parsed
descriptor, so it is tested on every platform. A descriptor is owner-only when:

- the owner is the current user;
- the DACL is present (a null DACL grants everyone everything);
- the DACL is protected and carries no inherited entry, so a later change to a
  parent directory cannot widen it;
- every allow entry, including inherit-only ones on a directory, names the
  current user or ``SYSTEM`` (which can read any file regardless);
- no entry is of a type this module does not understand.

Deny entries are always acceptable: they only ever narrow access.

Everything that touches Win32 is ``ctypes`` against ``advapi32`` and
``kernel32``, so no third-party package is needed.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

SYSTEM_SID = "S-1-5-18"

_ACCESS_ALLOWED_ACE_TYPE = 0x0
_ACCESS_DENIED_ACE_TYPE = 0x1
_INHERITED_ACE = 0x10
_SE_DACL_PRESENT = 0x0004
_SE_DACL_PROTECTED = 0x1000


class OwnerOnlyError(Exception):
    """The path is not provably owner-only, or its descriptor cannot be read."""


@dataclass(frozen=True)
class Ace:
    """One DACL entry, reduced to what the policy needs."""

    kind: Literal["allow", "deny", "other"]
    sid: str
    inherited: bool
    ace_type: int = 0


@dataclass(frozen=True)
class SecurityInfo:
    """The owner and DACL of one opened object. ``aces`` is ``None`` for a
    null DACL (no DACL, or a present-but-null one)."""

    owner_sid: str
    protected: bool
    aces: tuple[Ace, ...] | None


def owner_only_problem(info: SecurityInfo, user_sid: str) -> str | None:
    """Return why ``info`` is not owner-only for ``user_sid``, or ``None``."""
    if info.owner_sid != user_sid:
        return f"owned by {info.owner_sid}, not this account ({user_sid})"
    if info.aces is None:
        return "has a null DACL, which grants every account full access"
    if not info.protected:
        return "has an unprotected DACL, so it inherits entries from its parent"
    allowed = {user_sid, SYSTEM_SID}
    for ace in info.aces:
        if ace.inherited:
            return f"carries an inherited entry for {ace.sid}"
        if ace.kind == "other":
            return f"carries an entry of unsupported type 0x{ace.ace_type:02x} for {ace.sid}"
        if ace.kind == "allow" and ace.sid not in allowed:
            return f"grants access to {ace.sid}"
    return None


def owner_only_sddl(user_sid: str) -> str:
    """The descriptor this module creates: owned by the user, protected, full
    control for the user and ``SYSTEM`` only."""
    return f"O:{user_sid}D:P(A;;FA;;;{user_sid})(A;;FA;;;SY)"


# --- Win32 ------------------------------------------------------------------

_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_ACL_SIZE_INFORMATION_CLASS = 2
_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_SDDL_REVISION_1 = 1

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_READ_CONTROL = 0x00020000
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_FILE_SHARE_DELETE = 0x4
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000


def _require_windows() -> None:
    if os.name != "nt":
        raise OwnerOnlyError("Windows ACL verification is only available on Windows")


class _ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AceCount", ctypes.c_uint32),
        ("AclBytesInUse", ctypes.c_uint32),
        ("AclBytesFree", ctypes.c_uint32),
    ]


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", ctypes.c_ushort),
    ]


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.c_uint32),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_int),
    ]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime", ctypes.c_uint64),
        ("ftLastAccessTime", ctypes.c_uint64),
        ("ftLastWriteTime", ctypes.c_uint64),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


def _api():
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
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
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    kernel32.CreateDirectoryW.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    return advapi32, kernel32


_INVALID_HANDLE = ctypes.c_void_p(-1).value


def _winerror(what: str) -> OwnerOnlyError:
    code = ctypes.get_last_error()
    return OwnerOnlyError(f"{what} failed: {ctypes.FormatError(code).strip()} ({code})")


def _sid_string(advapi32, kernel32, psid: int) -> str:
    from ctypes import wintypes

    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(text)):
        raise _winerror("ConvertSidToStringSidW")
    try:
        return str(text.value)
    finally:
        kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def current_user_sid() -> str:
    """The SID of the user this process runs as (its token user, which is
    the same whether or not the token is elevated)."""
    _require_windows()
    from ctypes import wintypes

    advapi32, kernel32 = _api()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise _winerror("OpenProcessToken")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, _TOKEN_USER_CLASS, buf, needed, ctypes.byref(needed)
        ):
            raise _winerror("GetTokenInformation")
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        return _sid_string(advapi32, kernel32, psid)
    finally:
        kernel32.CloseHandle(token)


def security_of_handle(handle: int) -> SecurityInfo:
    """Read the owner and DACL of an open file or directory handle."""
    _require_windows()
    from ctypes import wintypes

    advapi32, kernel32 = _api()
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = advapi32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        raise OwnerOnlyError(f"GetSecurityInfo failed: {ctypes.FormatError(status).strip()}")
    try:
        if not owner.value:
            raise OwnerOnlyError("the security descriptor has no owner")
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise _winerror("GetSecurityDescriptorControl")
        owner_sid = _sid_string(advapi32, kernel32, owner.value)
        protected = bool(control.value & _SE_DACL_PROTECTED)
        if not (control.value & _SE_DACL_PRESENT) or not dacl.value:
            return SecurityInfo(owner_sid, protected, None)
        size = _ACL_SIZE_INFORMATION()
        if not advapi32.GetAclInformation(
            dacl, ctypes.byref(size), ctypes.sizeof(size), _ACL_SIZE_INFORMATION_CLASS
        ):
            raise _winerror("GetAclInformation")
        aces: list[Ace] = []
        for index in range(size.AceCount):
            entry = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(entry)):
                raise _winerror("GetAce")
            header = _ACE_HEADER.from_address(entry.value)
            inherited = bool(header.AceFlags & _INHERITED_ACE)
            if header.AceType in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE):
                # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE: header, mask, then the SID.
                sid = _sid_string(advapi32, kernel32, entry.value + 8)
                kind: Literal["allow", "deny", "other"] = (
                    "allow" if header.AceType == _ACCESS_ALLOWED_ACE_TYPE else "deny"
                )
            else:
                sid, kind = "?", "other"
            aces.append(Ace(kind, sid, inherited, header.AceType))
        return SecurityInfo(owner_sid, protected, tuple(aces))
    finally:
        kernel32.LocalFree(descriptor)


def _attributes(kernel32, handle: int) -> int:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise _winerror("GetFileInformationByHandle")
    return info.dwFileAttributes


def _open_no_follow(kernel32, path: Path, access: int) -> int:
    handle = kernel32.CreateFileW(
        str(path),
        access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle in (None, _INVALID_HANDLE):
        code = ctypes.get_last_error()
        if code in (2, 3):  # ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
            raise FileNotFoundError(str(path))
        raise OwnerOnlyError(f"cannot open {path}: {ctypes.FormatError(code).strip()} ({code})")
    return handle


def _verify_handle(kernel32, handle: int, path: Path, *, directory: bool) -> None:
    attributes = _attributes(kernel32, handle)
    if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise OwnerOnlyError(f"{path} is a symlink or other reparse point")
    if bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) != directory:
        raise OwnerOnlyError(f"{path} is not a {'directory' if directory else 'regular file'}")
    problem = owner_only_problem(security_of_handle(handle), current_user_sid())
    if problem is not None:
        raise OwnerOnlyError(f"{path} is not owner-only: it {problem}")


def check_owner_only_dir(path: Path) -> None:
    """Raise unless ``path`` is a real directory that is owner-only.
    Raises ``FileNotFoundError`` if it does not exist."""
    _require_windows()
    _, kernel32 = _api()
    handle = _open_no_follow(kernel32, Path(path), _READ_CONTROL | _FILE_READ_ATTRIBUTES)
    try:
        _verify_handle(kernel32, handle, Path(path), directory=True)
    finally:
        kernel32.CloseHandle(handle)


def open_owner_only_for_read(path: Path) -> int:
    """Open ``path`` without following a reparse point, verify the *opened*
    file is a regular, owner-only file, and return a CRT file descriptor for
    reading. Raises ``FileNotFoundError`` if it does not exist."""
    _require_windows()
    import msvcrt

    _, kernel32 = _api()
    handle = _open_no_follow(
        kernel32, Path(path), _GENERIC_READ | _READ_CONTROL | _FILE_READ_ATTRIBUTES
    )
    try:
        _verify_handle(kernel32, handle, Path(path), directory=False)
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
    return fd


def _owner_only_attributes(advapi32):
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        owner_only_sddl(current_user_sid()), _SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        raise _winerror("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    attributes = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor, 0)
    return attributes, descriptor


def create_owner_only_file(path: Path) -> int:
    """Create ``path`` exclusively with an owner-only, protected DACL and
    return a CRT file descriptor for writing. Raises ``FileExistsError`` if
    the path exists. The descriptor is applied at creation, so the file is
    never observable with a wider one."""
    _require_windows()
    import msvcrt

    advapi32, kernel32 = _api()
    attributes, descriptor = _owner_only_attributes(advapi32)
    try:
        handle = kernel32.CreateFileW(
            str(path),
            _GENERIC_WRITE | _READ_CONTROL,
            0,
            ctypes.byref(attributes),
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
    finally:
        kernel32.LocalFree(descriptor)
    if handle in (None, _INVALID_HANDLE):
        code = ctypes.get_last_error()
        if code in (80, 183):  # ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS
            raise FileExistsError(str(path))
        raise OwnerOnlyError(f"cannot create {path}: {ctypes.FormatError(code).strip()} ({code})")
    try:
        return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def create_owner_only_dir(path: Path) -> None:
    """Create one directory with an owner-only, protected DACL. Raises
    ``FileExistsError`` if it exists; the parent must already exist."""
    _require_windows()
    advapi32, kernel32 = _api()
    attributes, descriptor = _owner_only_attributes(advapi32)
    try:
        if not kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            code = ctypes.get_last_error()
            if code == 183:  # ERROR_ALREADY_EXISTS
                raise FileExistsError(str(path))
            raise OwnerOnlyError(
                f"cannot create directory {path}: {ctypes.FormatError(code).strip()} ({code})"
            )
    finally:
        kernel32.LocalFree(descriptor)
