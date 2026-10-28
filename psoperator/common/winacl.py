"""Windows owner-only verification through the file's security descriptor (D-01).

POSIX code proves a secret is private with ``fstat``: owner uid and mode
``0600``. Windows has no mode bits; who can read a file is its DACL. This
module is the Windows counterpart. It reads the owner and DACL from an *open
handle*, never from a path checked first and opened later, and it creates
files and directories with an explicit, protected DACL applied at creation,
so nothing is inherited from the parent.

The policy is :func:`owner_only_problem`, a pure function over the parsed
descriptor, so it is tested on every platform. A descriptor is owner-only when:

- the owner is the current user;
- the DACL is present (a null DACL grants everyone everything);
- the DACL is protected and carries no inherited entry, so a later change to a
  parent directory cannot widen it;
- every allow entry, including inherit-only ones on a directory, names the
  current user or ``SYSTEM``;
- no entry is of a type this module does not parse.

Deny entries are always acceptable: they only ever narrow access. Allowing
``SYSTEM`` is a policy choice (services and the OS run as it), not a claim
that the DACL is irrelevant to it. An administrator who elevates can take
ownership of any file; this boundary assumes the planner account cannot
elevate.

A directory that is about to receive a first private directory is held to a
weaker rule, :func:`trusted_parent_problem`, the counterpart of the POSIX
"owned by this account or root, not writable by group or other". Profile and
project folders inherit entries for ``SYSTEM`` and Administrators, so the
strict rule would refuse every ordinary location. Here Administrators play
the part root plays on POSIX: the parent may be owned by the user, ``SYSTEM``
or Administrators, and only those (and ``OWNER RIGHTS``, which stands for the
owner) may hold a right that adds, removes or renames its entries.

Creation is anchored like the POSIX ``dir_fd`` path: :class:`OwnerOnlyDir`
holds a verified directory handle, and files and subdirectories are created
relative to that handle (``NtCreateFile`` with ``RootDirectory`` and
``OBJ_DONT_REPARSE``), so swapping an ancestor for a junction after the check
cannot redirect them. Names are single path components; a colon, which would
name an alternate data stream sharing another file's descriptor, is refused.

Everything that touches Win32 is ``ctypes`` against ``advapi32``,
``kernel32`` and ``ntdll``, so no third-party package is needed.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Literal

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
OWNER_RIGHTS_SID = "S-1-3-4"
_MAX_COMPONENT_UTF16 = 255

_ACCESS_ALLOWED_ACE_TYPE = 0x0
_ACCESS_DENIED_ACE_TYPE = 0x1
_INHERIT_ONLY_ACE = 0x08
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
    mask: int = 0
    inherit_only: bool = False


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


#: Rights that let an account add, remove or rename a directory's entries, or
#: give itself those rights: add file, add subdirectory, delete child, delete,
#: write DAC, write owner, generic write and generic all. MAXIMUM_ALLOWED is an
#: access-request selector, not a right an entry grants; an entry carrying it
#: is malformed or deliberately odd, and is refused conservatively.
_CHANGES_ENTRIES = (
    0x2 | 0x4 | 0x40 | 0x00010000 | 0x00040000 | 0x00080000 | 0x02000000 | 0x10000000 | 0x40000000
)


def trusted_parent_problem(info: SecurityInfo, user_sid: str) -> str | None:
    """Return why the directory described by ``info`` is not a safe parent for
    a new private directory, or ``None``. An account that can change its
    entries could move a private directory away, or put another in its place.
    An inherit-only entry is skipped: it applies only to children, and the
    children made here get an explicit, protected DACL."""
    trusted = {user_sid, SYSTEM_SID, ADMINISTRATORS_SID}
    if info.owner_sid not in trusted:
        return f"owned by {info.owner_sid}, not this account, SYSTEM or Administrators"
    if info.aces is None:
        return "has a null DACL, which grants every account full access"
    for ace in info.aces:
        if ace.inherit_only or ace.kind == "deny":
            continue
        if ace.kind == "other":
            return f"carries an entry of unsupported type 0x{ace.ace_type:02x} for {ace.sid}"
        if ace.mask & _CHANGES_ENTRIES and ace.sid not in trusted | {OWNER_RIGHTS_SID}:
            return f"lets {ace.sid} change its entries (access 0x{ace.mask:08x})"
    return None


def owner_only_sddl(user_sid: str) -> str:
    """The descriptor this module creates: owned by the user, protected, full
    control for the user and ``SYSTEM`` only."""
    return f"O:{user_sid}D:P(A;;FA;;;{user_sid})(A;;FA;;;SY)"


def component_problem(name: str) -> str | None:
    """Why ``name`` is not one plain path component, or ``None``. A colon
    would name an alternate data stream of another file."""
    if not name or name in (".", ".."):
        return f"{name!r} is not a file name"
    for bad in ("\\", "/", ":", "\x00"):
        if bad in name:
            return f"{name!r} contains {bad!r}"
    # NTFS caps a component at 255 UTF-16 units; this also keeps the byte
    # length inside the USHORT of the UNICODE_STRING passed to NtCreateFile.
    if len(name.encode("utf-16-le")) > _MAX_COMPONENT_UTF16 * 2:
        return f"a name of {len(name)} characters is longer than {_MAX_COMPONENT_UTF16} units"
    return None


def path_problem(path: Path) -> str | None:
    """Why ``path`` may not be opened by path, or ``None``: every component
    after the drive or share must be a plain name, so no component can name
    an alternate data stream."""
    parts = PureWindowsPath(str(path)).parts
    anchor = PureWindowsPath(str(path)).anchor
    for part in parts[1:] if anchor else parts:
        problem = component_problem(part)
        if problem is not None and part not in (".", ".."):
            return problem
    return None


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
_SYNCHRONIZE = 0x00100000
_READ_CONTROL = 0x00020000
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_TRAVERSE = 0x0020
_FILE_ADD_FILE = 0x0002
_DELETE = 0x00010000
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_FILE_SHARE_DELETE = 0x4
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

# NtCreateFile
_FILE_OPEN = 1
_FILE_CREATE = 2
_FILE_DIRECTORY_FILE = 0x00000001
_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
_FILE_NON_DIRECTORY_FILE = 0x00000040
_FILE_DELETE_ON_CLOSE = 0x00001000
_FILE_RENAME_INFORMATION_CLASS = 10
_FILE_OPEN_REPARSE_POINT = 0x00200000
_OBJ_CASE_INSENSITIVE = 0x00000040
_OBJ_DONT_REPARSE = 0x00001000
_STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
_STATUS_OBJECT_NAME_COLLISION = 0xC0000035
_STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A


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


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.c_void_p),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ulong),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", ctypes.c_ulong),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_void_p)]


def _api():
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")

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

    ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    ]
    ntdll.NtCreateFile.restype = ctypes.c_long
    ntdll.NtSetInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_int,
    ]
    ntdll.NtSetInformationFile.restype = ctypes.c_long
    ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
    ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    return advapi32, kernel32, ntdll


_INVALID_HANDLE = ctypes.c_void_p(-1).value
# A held directory: enough to read its descriptor and work below it. No
# delete sharing, so it cannot be renamed or removed while held.
_DIR_ACCESS = _READ_CONTROL | _FILE_READ_ATTRIBUTES | _FILE_TRAVERSE | _SYNCHRONIZE
_DIR_SHARE = _FILE_SHARE_READ | _FILE_SHARE_WRITE


def _error(what: str, code: int) -> OwnerOnlyError:
    return OwnerOnlyError(f"{what} failed: {ctypes.FormatError(code).strip()} ({code})")


def _sid_string(advapi32, kernel32, psid: int) -> str:
    from ctypes import wintypes

    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(text)):
        raise _error("ConvertSidToStringSidW", ctypes.get_last_error())
    try:
        return str(text.value)
    finally:
        kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def current_user_sid() -> str:
    """The SID of the user this process runs as (its token user, which is
    the same whether or not the token is elevated)."""
    _require_windows()
    from ctypes import wintypes

    advapi32, kernel32, _ = _api()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise _error("OpenProcessToken", ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, _TOKEN_USER_CLASS, buf, needed, ctypes.byref(needed)
        ):
            raise _error("GetTokenInformation", ctypes.get_last_error())
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        return _sid_string(advapi32, kernel32, psid)
    finally:
        kernel32.CloseHandle(token)


def security_of_handle(handle: int) -> SecurityInfo:
    """Read the owner and DACL of an open file or directory handle."""
    _require_windows()
    from ctypes import wintypes

    advapi32, kernel32, _ = _api()
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
        raise _error("GetSecurityInfo", status)
    try:
        if not owner.value:
            raise OwnerOnlyError("the security descriptor has no owner")
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise _error("GetSecurityDescriptorControl", ctypes.get_last_error())
        owner_sid = _sid_string(advapi32, kernel32, owner.value)
        protected = bool(control.value & _SE_DACL_PROTECTED)
        if not (control.value & _SE_DACL_PRESENT) or not dacl.value:
            return SecurityInfo(owner_sid, protected, None)
        size = _ACL_SIZE_INFORMATION()
        if not advapi32.GetAclInformation(
            dacl, ctypes.byref(size), ctypes.sizeof(size), _ACL_SIZE_INFORMATION_CLASS
        ):
            raise _error("GetAclInformation", ctypes.get_last_error())
        aces: list[Ace] = []
        for index in range(size.AceCount):
            entry = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(entry)):
                raise _error("GetAce", ctypes.get_last_error())
            header = _ACE_HEADER.from_address(entry.value)
            inherited = bool(header.AceFlags & _INHERITED_ACE)
            inherit_only = bool(header.AceFlags & _INHERIT_ONLY_ACE)
            mask = 0
            if header.AceType in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE):
                # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE: header, mask, then the SID.
                mask = ctypes.c_uint32.from_address(entry.value + 4).value
                sid = _sid_string(advapi32, kernel32, entry.value + 8)
                kind: Literal["allow", "deny", "other"] = (
                    "allow" if header.AceType == _ACCESS_ALLOWED_ACE_TYPE else "deny"
                )
            else:
                sid, kind = "?", "other"
            aces.append(Ace(kind, sid, inherited, header.AceType, mask, inherit_only))
        return SecurityInfo(owner_sid, protected, tuple(aces))
    finally:
        kernel32.LocalFree(descriptor)


def _attributes(kernel32, handle: int) -> int:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise _error("GetFileInformationByHandle", ctypes.get_last_error())
    return info.dwFileAttributes


def _verify_handle(kernel32, handle: int, where: str, *, directory: bool) -> None:
    attributes = _attributes(kernel32, handle)
    if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise OwnerOnlyError(f"{where} is a symlink or other reparse point")
    if bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) != directory:
        raise OwnerOnlyError(f"{where} is not a {'directory' if directory else 'regular file'}")
    problem = owner_only_problem(security_of_handle(handle), current_user_sid())
    if problem is not None:
        raise OwnerOnlyError(f"{where} is not owner-only: it {problem}")


def _check_path(path: Path) -> None:
    problem = path_problem(path)
    if problem is not None:
        raise OwnerOnlyError(f"refusing path {path}: {problem}")


def _open_no_follow(kernel32, path: Path, access: int, share: int) -> int:
    _check_path(path)
    handle = kernel32.CreateFileW(
        str(path),
        access,
        share,
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


def check_owner_only_dir(path: Path) -> None:
    """Raise unless ``path`` is a real directory that is owner-only.
    Raises ``FileNotFoundError`` if it does not exist."""
    with OwnerOnlyDir(path):
        pass


def open_owner_only_for_read(path: Path) -> int:
    """Open ``path`` without following a reparse point, verify the *opened*
    file is a regular, owner-only file, and return a CRT file descriptor for
    reading that file. Raises ``FileNotFoundError`` if it does not exist.
    The open shares read only, so it is refused while another handle may be
    writing, deleting or renaming the file, and none can start while it is
    held."""
    _require_windows()
    import msvcrt

    _, kernel32, _ = _api()
    handle = _open_no_follow(
        kernel32,
        Path(path),
        _GENERIC_READ | _READ_CONTROL | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ,
    )
    try:
        _verify_handle(kernel32, handle, str(path), directory=False)
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def check_trusted_parent(path: Path) -> None:
    """Raise unless ``path`` is a real directory that is a safe parent for a
    new private directory (:func:`trusted_parent_problem`). Raises
    ``FileNotFoundError`` if it does not exist."""
    _require_windows()
    _, kernel32, _ = _api()
    # Metadata only (no data access), so Windows applies no share-mode check
    # to this open whatever the share flags say; it is a point-in-time policy
    # check, like the POSIX stat of the ancestor.
    handle = _open_no_follow(
        kernel32,
        Path(path),
        _READ_CONTROL | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
    )
    try:
        _verify_parent(kernel32, handle, str(path))
    finally:
        kernel32.CloseHandle(handle)


def _verify_parent(kernel32, handle: int, where: str) -> None:
    attributes = _attributes(kernel32, handle)
    if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise OwnerOnlyError(f"{where} is a symlink or other reparse point")
    if not attributes & _FILE_ATTRIBUTE_DIRECTORY:
        raise OwnerOnlyError(f"{where} is not a directory")
    problem = trusted_parent_problem(security_of_handle(handle), current_user_sid())
    if problem is not None:
        raise OwnerOnlyError(f"{where} is not a safe parent: it {problem}")


def _owner_only_descriptor(advapi32) -> ctypes.c_void_p:
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        owner_only_sddl(current_user_sid()), _SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        raise _error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW", ctypes.get_last_error()
        )
    return descriptor


def create_owner_only_dir(path: Path) -> None:
    """Create one directory by path with an owner-only, protected DACL. For a
    directory whose parent is not itself owner-only (the first private
    directory under a profile). Below a verified directory, use
    :meth:`OwnerOnlyDir.create_dir`. Raises ``FileExistsError`` if it exists."""
    _require_windows()
    _check_path(Path(path))
    advapi32, kernel32, _ = _api()
    descriptor = _owner_only_descriptor(advapi32)
    attributes = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor, 0)
    try:
        created = kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes))
        code = ctypes.get_last_error()
    finally:
        kernel32.LocalFree(descriptor)
    if not created:
        if code == 183:  # ERROR_ALREADY_EXISTS
            raise FileExistsError(str(path))
        raise _error(f"creating directory {path}", code)


def ensure_owner_only_dir(path: Path) -> "OwnerOnlyDir":
    """Return ``path`` held as an :class:`OwnerOnlyDir`, creating every missing
    component owner-only first.

    Creation is anchored: the nearest existing ancestor is held and must be a
    trusted parent (:func:`trusted_parent_problem`), and each missing component
    is created and then opened relative to the handle on the one before it, so
    no component is ever reached by path after its parent was checked. A
    component that appears meanwhile is opened the same way and must be
    owner-only. Existing ancestors above the nearest one are not judged, as on
    POSIX."""
    _require_windows()
    target = Path(path)
    missing: list[str] = []
    current = target
    while not os.path.lexists(current):
        if current.parent == current:
            raise FileNotFoundError(f"no existing ancestor of {target}")
        missing.append(current.name)
        current = current.parent
    if not missing:
        return OwnerOnlyDir(target)
    held = OwnerOnlyDir(current, _parent=True)
    try:
        for name in reversed(missing):
            try:
                held.create_dir(name)
            except FileExistsError:
                pass  # made meanwhile; open_dir judges it
            child = held.open_dir(name)
            held.close()
            held = child
    except BaseException:
        held.close()
        raise
    return held


def _rename_information(root: int, name: str) -> ctypes.Structure:
    """FILE_RENAME_INFORMATION for ``name`` relative to ``root``, replacing."""
    from ctypes import wintypes

    # Sized in UTF-16 units, not code points: a character outside the BMP is
    # two units, and FileNameLength must not run past the array.
    encoded = name.encode("utf-16-le")

    class _FILE_RENAME_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", ctypes.c_ubyte),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.ULONG),
            ("FileName", ctypes.c_ubyte * len(encoded)),
        ]

    information = _FILE_RENAME_INFORMATION(1, root, len(encoded))
    ctypes.memmove(information.FileName, encoded, len(encoded))
    return information


class OwnerOnlyDir:
    """A verified owner-only directory, held open for anchored operations.

    The handle is opened without following a reparse point and without
    ``FILE_SHARE_DELETE``, so the directory cannot be renamed or removed while
    held, and every create or open below it is relative to this handle.
    """

    def __init__(self, path: Path, *, _parent: bool = False) -> None:
        _require_windows()
        self.path = Path(path)
        _, kernel32, _ = _api()
        self._handle = _open_no_follow(kernel32, self.path, _DIR_ACCESS, _DIR_SHARE)
        self._verify(kernel32, parent=_parent)

    def _verify(self, kernel32, *, parent: bool) -> None:
        """Verify the held handle, owner-only (or, for the anchor of
        :func:`ensure_owner_only_dir`, a trusted parent); close it if not."""
        try:
            if parent:
                _verify_parent(kernel32, self._handle, str(self.path))
            else:
                _verify_handle(kernel32, self._handle, str(self.path), directory=True)
        except BaseException:
            kernel32.CloseHandle(self._handle)
            self._handle = None
            raise

    def __enter__(self) -> "OwnerOnlyDir":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self._handle is not None:
            _, kernel32, _ = _api()
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def _held(self) -> int:
        if self._handle is None:
            raise OwnerOnlyError(f"{self.path} is closed")
        return self._handle

    def _checked(self, name: str) -> str:
        problem = component_problem(name)
        if problem is not None:
            raise OwnerOnlyError(f"refusing name in {self.path}: {problem}")
        return name

    def _nt_create(
        self, name: str, access: int, disposition: int, options: int, descriptor, share=None
    ) -> int:
        self._checked(name)
        return self._nt_open(name, access, disposition, options, descriptor, share)

    def _nt_open(
        self, name: str, access: int, disposition: int, options: int, descriptor, share=None
    ) -> int:
        """``NtCreateFile`` relative to the held handle. An empty ``name``
        opens the held directory itself. ``share`` defaults to read sharing
        for an open and none for a create."""
        from ctypes import wintypes

        root = self._held()
        _, _, ntdll = _api()
        buffer = ctypes.create_unicode_buffer(name)
        length = len(name.encode("utf-16-le"))
        unicode_name = _UNICODE_STRING(length, length, ctypes.addressof(buffer))
        attributes = _OBJECT_ATTRIBUTES(
            ctypes.sizeof(_OBJECT_ATTRIBUTES),
            root,
            ctypes.pointer(unicode_name),
            _OBJ_CASE_INSENSITIVE | _OBJ_DONT_REPARSE,
            descriptor,
            None,
        )
        handle = wintypes.HANDLE()
        io_status = _IO_STATUS_BLOCK()
        status = ntdll.NtCreateFile(
            ctypes.byref(handle),
            access | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            _FILE_ATTRIBUTE_NORMAL,
            share if share is not None else (_FILE_SHARE_READ if disposition == _FILE_OPEN else 0),
            disposition,
            options | _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )
        unsigned = status & 0xFFFFFFFF
        if unsigned == _STATUS_OBJECT_NAME_COLLISION:
            raise FileExistsError(str(self.path / name))
        if unsigned in (_STATUS_OBJECT_NAME_NOT_FOUND, _STATUS_OBJECT_PATH_NOT_FOUND):
            raise FileNotFoundError(str(self.path / name))
        if status < 0:
            raise _error(
                f"NtCreateFile for {self.path / name}", ntdll.RtlNtStatusToDosError(status)
            )
        return handle.value

    def create_file(self, name: str) -> int:
        """Create ``name`` in this directory exclusively, owner-only, and
        return a CRT file descriptor for writing. The descriptor is applied
        at creation. The handle may delete, so :meth:`replace` can rename it.
        Raises ``FileExistsError`` if it exists."""
        import msvcrt

        advapi32, kernel32, _ = _api()
        descriptor = _owner_only_descriptor(advapi32)
        try:
            handle = self._nt_create(
                name,
                _GENERIC_WRITE | _READ_CONTROL | _DELETE,
                _FILE_CREATE,
                _FILE_NON_DIRECTORY_FILE,
                descriptor,
            )
        finally:
            kernel32.LocalFree(descriptor)
        try:
            return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        except BaseException:
            kernel32.CloseHandle(handle)
            raise

    def create_dir(self, name: str) -> None:
        """Create subdirectory ``name`` owner-only. Raises ``FileExistsError``
        if it exists."""
        advapi32, kernel32, _ = _api()
        descriptor = _owner_only_descriptor(advapi32)
        try:
            handle = self._nt_create(
                name, _READ_CONTROL, _FILE_CREATE, _FILE_DIRECTORY_FILE, descriptor
            )
        finally:
            kernel32.LocalFree(descriptor)
        kernel32.CloseHandle(handle)

    def open_dir(self, name: str) -> "OwnerOnlyDir":
        """Open subdirectory ``name`` relative to this handle, verify it is
        owner-only, and return it held. Raises ``FileNotFoundError`` if it does
        not exist."""
        _, kernel32, _ = _api()
        handle = self._nt_create(
            name, _DIR_ACCESS, _FILE_OPEN, _FILE_DIRECTORY_FILE, None, _DIR_SHARE
        )
        child = OwnerOnlyDir.__new__(OwnerOnlyDir)
        child.path = self.path / name
        child._handle = handle
        child._verify(kernel32, parent=False)
        return child

    def open_file(self, name: str) -> int:
        """Open ``name`` in this directory for reading, verify the opened file
        is a regular owner-only file, and return a CRT file descriptor.
        Raises ``FileNotFoundError`` if it does not exist."""
        import msvcrt

        _, kernel32, _ = _api()
        handle = self._nt_create(
            name,
            _GENERIC_READ | _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            _FILE_OPEN,
            _FILE_NON_DIRECTORY_FILE,
            None,
        )
        try:
            _verify_handle(kernel32, handle, str(self.path / name), directory=False)
            return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            kernel32.CloseHandle(handle)
            raise

    def replace(self, fd: int, name: str) -> None:
        """Rename the file open as ``fd`` (from :meth:`create_file`) to
        ``name`` in this directory, replacing any file of that name. The
        target is resolved relative to the held handle, like creation. It
        fails while any handle holds the old file open, so a reader never has
        its file replaced underneath it."""
        import msvcrt

        root = self._held()
        _, _, ntdll = _api()
        information = _rename_information(root, self._checked(name))
        io_status = _IO_STATUS_BLOCK()
        status = ntdll.NtSetInformationFile(
            msvcrt.get_osfhandle(fd),
            ctypes.byref(io_status),
            ctypes.byref(information),
            ctypes.sizeof(information),
            _FILE_RENAME_INFORMATION_CLASS,
        )
        if status < 0:
            raise _error(f"renaming to {self.path / name}", ntdll.RtlNtStatusToDosError(status))

    def unlink(self, name: str) -> None:
        """Remove file ``name`` from this directory (a symlink itself, never
        its target). Raises ``FileNotFoundError`` if it does not exist."""
        _, kernel32, _ = _api()
        handle = self._nt_create(
            name, _DELETE, _FILE_OPEN, _FILE_NON_DIRECTORY_FILE | _FILE_DELETE_ON_CLOSE, None
        )
        kernel32.CloseHandle(handle)

    def sync(self) -> None:
        """Flush this directory, so a rename into it is durable."""
        _, kernel32, _ = _api()
        handle = self._nt_open("", _FILE_ADD_FILE, _FILE_OPEN, _FILE_DIRECTORY_FILE, None)
        try:
            if not kernel32.FlushFileBuffers(handle):
                raise _error(f"flushing {self.path}", ctypes.get_last_error())
        finally:
            kernel32.CloseHandle(handle)
