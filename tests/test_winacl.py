"""Windows owner-only verification (D-01).

The policy, name rules and structure layout are pure and pinned on every
platform, each rule with a negative control. Descriptor reading, anchored
creation and the alternate-data-stream and junction cases run against real
files on Windows only.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from pathlib import Path

import pytest

from psoperator.common import winacl
from psoperator.common.winacl import (
    SYSTEM_SID,
    Ace,
    OwnerOnlyDir,
    OwnerOnlyError,
    SecurityInfo,
    component_problem,
    owner_only_problem,
    owner_only_sddl,
    path_problem,
)

USER = "S-1-5-21-1-2-3-1001"
EVERYONE = "S-1-1-0"
ADMINISTRATORS = "S-1-5-32-544"
CREATOR_OWNER = "S-1-3-0"
OWNER_RIGHTS = "S-1-3-4"

windows_only = pytest.mark.skipif(os.name != "nt", reason="real Windows descriptors")


def _info(*aces: Ace, owner: str = USER, protected: bool = True) -> SecurityInfo:
    return SecurityInfo(owner, protected, tuple(aces))


def _allow(sid: str, inherited: bool = False) -> Ace:
    return Ace("allow", sid, inherited)


# --- policy -----------------------------------------------------------------


def test_owner_and_system_only_is_owner_only():
    assert owner_only_problem(_info(_allow(USER), _allow(SYSTEM_SID)), USER) is None


def test_a_deny_entry_for_anyone_is_acceptable():
    info = _info(_allow(USER), Ace("deny", EVERYONE, False))
    assert owner_only_problem(info, USER) is None


def test_an_empty_dacl_grants_nobody_and_is_owner_only():
    assert owner_only_problem(_info(), USER) is None


@pytest.mark.parametrize(
    "info, expected",
    [
        (_info(_allow(USER), owner=ADMINISTRATORS), "owned by"),
        (SecurityInfo(USER, True, None), "null DACL"),
        (_info(_allow(USER), protected=False), "unprotected"),
        (_info(_allow(USER), _allow(SYSTEM_SID, inherited=True)), "inherited"),
        (_info(_allow(USER), _allow(EVERYONE)), f"grants access to {EVERYONE}"),
        (_info(_allow(USER), _allow(ADMINISTRATORS)), f"grants access to {ADMINISTRATORS}"),
        (_info(_allow(USER), _allow(CREATOR_OWNER)), f"grants access to {CREATOR_OWNER}"),
        (_info(_allow(USER), _allow(OWNER_RIGHTS)), f"grants access to {OWNER_RIGHTS}"),
        (_info(_allow(USER), Ace("other", "?", False, 0x5)), "unsupported type 0x05"),
        (_info(_allow(USER), Ace("other", "?", False, 0x9)), "unsupported type 0x09"),
    ],
    ids=[
        "wrong-owner",
        "null-dacl",
        "unprotected",
        "inherited",
        "everyone",
        "admins",
        "creator-owner",
        "owner-rights",
        "object-ace",
        "callback-ace",
    ],
)
def test_each_rule_refuses(info, expected):
    problem = owner_only_problem(info, USER)
    assert problem is not None and expected in problem


def test_the_created_descriptor_names_only_the_user_and_system():
    assert owner_only_sddl(USER) == f"O:{USER}D:P(A;;FA;;;{USER})(A;;FA;;;SY)"


# --- names and paths ----------------------------------------------------------


def test_a_plain_name_is_accepted():
    assert component_problem("gate-state.json") is None


@pytest.mark.parametrize("name", ["", ".", "..", "a:b", "a\\b", "a/b", "a\x00b", "f::$DATA"])
def test_a_name_that_is_not_one_plain_component_is_refused(name):
    assert component_problem(name) is not None


def test_a_name_longer_than_ntfs_allows_is_refused():
    # 255 UTF-16 units fit; a non-BMP character takes two units.
    assert component_problem("a" * 255) is None
    assert component_problem("a" * 256) is not None
    assert component_problem("\U0001f600" * 128) is not None
    # A USHORT wraps at 32768 characters; this must be refused, not truncated.
    assert component_problem("a" * 32769) is not None


@pytest.mark.parametrize("path", [r"C:\keys\observer.json", "keys/observer.json", r"\\host\s\k"])
def test_a_plain_path_is_accepted(path):
    assert path_problem(Path(path)) is None


@pytest.mark.parametrize(
    "path", [r"C:\keys\observer.json:hidden", "keys/base:stream", r"C:\keys:s\observer.json"]
)
def test_a_path_naming_an_alternate_data_stream_is_refused(path):
    assert path_problem(Path(path)) is not None


def test_by_handle_file_information_has_the_win32_layout():
    layout = winacl._BY_HANDLE_FILE_INFORMATION
    assert ctypes.sizeof(layout) == 52
    assert layout.ftCreationTime.offset == 4
    assert layout.dwVolumeSerialNumber.offset == 28
    assert layout.nFileIndexLow.offset == 48


def test_the_nt_structures_have_the_native_layout():
    pointer = ctypes.sizeof(ctypes.c_void_p)
    assert pointer in (4, 8)
    # UNICODE_STRING: two USHORTs, then a pointer aligned to pointer size.
    assert ctypes.sizeof(winacl._UNICODE_STRING) == (16 if pointer == 8 else 8)
    assert winacl._UNICODE_STRING.Buffer.offset == pointer
    # OBJECT_ATTRIBUTES: ULONG Length; RootDirectory, ObjectName; ULONG Attributes;
    # SecurityDescriptor, SecurityQualityOfService (four pointers, two ULONGs).
    assert ctypes.sizeof(winacl._OBJECT_ATTRIBUTES) == (48 if pointer == 8 else 24)
    assert winacl._OBJECT_ATTRIBUTES.RootDirectory.offset == pointer
    assert winacl._OBJECT_ATTRIBUTES.Attributes.offset == 3 * pointer
    # IO_STATUS_BLOCK: a pointer-sized union and a ULONG_PTR.
    assert ctypes.sizeof(winacl._IO_STATUS_BLOCK) == 2 * pointer


@pytest.mark.skipif(os.name == "nt", reason="the non-Windows refusal")
def test_off_windows_every_operation_refuses(tmp_path):
    for call in (
        winacl.current_user_sid,
        lambda: winacl.check_owner_only_dir(tmp_path),
        lambda: winacl.open_owner_only_for_read(tmp_path / "x"),
        lambda: winacl.create_owner_only_dir(tmp_path / "d"),
        lambda: OwnerOnlyDir(tmp_path),
    ):
        with pytest.raises(OwnerOnlyError):
            call()


# --- real descriptors (Windows) ---------------------------------------------


def _grant(path, sid: str) -> None:
    subprocess.run(["icacls", str(path), "/grant", f"*{sid}:(R)"], check=True, capture_output=True)


def _set_dacl(path, sddl: str) -> None:
    """Replace the DACL of ``path`` with the protected DACL in ``sddl``."""
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32")
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    assert advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ), ctypes.get_last_error()
    try:
        # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        assert advapi32.SetFileSecurityW(str(path), 0x4 | 0x80000000, descriptor), (
            ctypes.get_last_error()
        )
    finally:
        kernel32.LocalFree(descriptor)


@pytest.fixture
def vault(tmp_path):
    """An owner-only directory under the (inheriting) pytest temp dir."""
    path = tmp_path / "vault"
    winacl.create_owner_only_dir(path)
    return path


def _write(directory: Path, name: str, data: bytes) -> None:
    with OwnerOnlyDir(directory) as held:
        fd = held.create_file(name)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


@windows_only
def test_current_user_sid_is_a_user_sid():
    assert winacl.current_user_sid().startswith("S-1-5-")


@windows_only
def test_a_created_file_is_owner_only_and_reads_back(vault):
    _write(vault, "secret", b"material")
    fd = winacl.open_owner_only_for_read(vault / "secret")
    try:
        assert os.read(fd, 100) == b"material"
    finally:
        os.close(fd)
    with OwnerOnlyDir(vault) as held:
        fd = held.open_file("secret")
    try:
        assert os.read(fd, 100) == b"material"
    finally:
        os.close(fd)


@windows_only
def test_a_created_file_carries_exactly_the_owner_only_descriptor(vault):
    import msvcrt

    _write(vault, "secret", b"x")
    fd = winacl.open_owner_only_for_read(vault / "secret")
    try:
        info = winacl.security_of_handle(msvcrt.get_osfhandle(fd))
    finally:
        os.close(fd)
    user = winacl.current_user_sid()
    assert info.owner_sid == user
    assert info.protected
    assert info.aces is not None
    assert {(a.kind, a.sid, a.inherited) for a in info.aces} == {
        ("allow", user, False),
        ("allow", SYSTEM_SID, False),
    }


@windows_only
def test_creating_over_an_existing_file_refuses(vault):
    _write(vault, "secret", b"x")
    with OwnerOnlyDir(vault) as held, pytest.raises(FileExistsError):
        held.create_file("secret")


@windows_only
def test_a_normally_created_file_is_refused(vault):
    plain = vault.parent / "plain"
    plain.write_bytes(b"x")
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.open_owner_only_for_read(plain)


@windows_only
def test_an_extra_allow_entry_is_refused(vault):
    _write(vault, "secret", b"x")
    _grant(vault / "secret", EVERYONE)
    with pytest.raises(OwnerOnlyError, match=f"grants access to {EVERYONE}"):
        winacl.open_owner_only_for_read(vault / "secret")
    with OwnerOnlyDir(vault) as held, pytest.raises(OwnerOnlyError, match="grants access"):
        held.open_file("secret")


@windows_only
def test_a_missing_file_is_not_found(vault):
    with pytest.raises(FileNotFoundError):
        winacl.open_owner_only_for_read(vault / "missing")
    with OwnerOnlyDir(vault) as held, pytest.raises(FileNotFoundError):
        held.open_file("missing")


@windows_only
def test_a_directory_is_not_read_as_a_file(vault):
    with OwnerOnlyDir(vault) as held:
        held.create_dir("sub")
        with pytest.raises(OwnerOnlyError):
            held.open_file("sub")
    with pytest.raises(OwnerOnlyError, match="not a regular file"):
        winacl.open_owner_only_for_read(vault / "sub")


@windows_only
def test_created_directories_are_owner_only(vault):
    winacl.check_owner_only_dir(vault)
    with OwnerOnlyDir(vault) as held:
        held.create_dir("sub")
        with pytest.raises(FileExistsError):
            held.create_dir("sub")
    winacl.check_owner_only_dir(vault / "sub")
    with pytest.raises(FileExistsError):
        winacl.create_owner_only_dir(vault)


@windows_only
def test_a_normally_created_directory_is_refused(tmp_path):
    (tmp_path / "plain").mkdir()
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.check_owner_only_dir(tmp_path / "plain")


@windows_only
def test_an_extra_allow_entry_on_a_directory_is_refused(vault):
    _grant(vault, EVERYONE)
    with pytest.raises(OwnerOnlyError, match=f"grants access to {EVERYONE}"):
        winacl.check_owner_only_dir(vault)


@windows_only
@pytest.mark.parametrize(
    "extra, expected",
    [
        ("(A;OICIIO;FA;;;WD)", f"grants access to {EVERYONE}"),
        ("(A;OICIIO;FA;;;CO)", f"grants access to {CREATOR_OWNER}"),
        ("(A;;FA;;;OW)", f"grants access to {OWNER_RIGHTS}"),
        ("(XA;;FR;;;WD;(Member_of {SID(BA)}))", "unsupported type 0x09"),
    ],
    ids=["inherit-only-everyone", "creator-owner", "owner-rights", "callback-ace"],
)
def test_real_descriptors_with_a_foreign_entry_are_refused(vault, extra, expected):
    user = winacl.current_user_sid()
    _set_dacl(vault, f"D:P(A;;FA;;;{user}){extra}")
    with pytest.raises(OwnerOnlyError, match=expected.replace("(", r"\(")):
        winacl.check_owner_only_dir(vault)


@windows_only
def test_a_stream_on_a_readable_file_is_never_created(vault):
    # The exploit: a base file Everyone can read. A stream created on it
    # shares that descriptor, whatever descriptor creation asked for.
    _write(vault, "base", b"x")
    _grant(vault / "base", EVERYONE)
    with OwnerOnlyDir(vault) as held, pytest.raises(OwnerOnlyError, match="contains ':'"):
        held.create_file("base:stream")
    with pytest.raises(OwnerOnlyError, match="contains ':'"):
        winacl.create_owner_only_dir(Path(f"{vault / 'base'}:stream"))
    assert not os.path.exists(f"{vault / 'base'}:stream")


@windows_only
def test_an_existing_stream_on_a_readable_file_is_not_read(vault):
    _write(vault, "base", b"x")
    _grant(vault / "base", EVERYONE)
    stream = f"{vault / 'base'}:stream"
    with open(stream, "wb") as handle:  # a real stream, readable by Everyone
        handle.write(b"planted")
    assert os.path.exists(stream)
    with pytest.raises(OwnerOnlyError, match="contains ':'"):
        winacl.open_owner_only_for_read(Path(stream))


@windows_only
def test_anchored_creation_passes_the_held_handle_as_root(vault, monkeypatch):
    # Deterministic: the filesystem test below cannot reach its swap branch
    # on NTFS, so pin the native call itself. Removing the anchoring (no
    # RootDirectory, a full path, or no OBJ_DONT_REPARSE) fails here.
    calls = []
    real_api = winacl._api

    class _NtDll:
        @staticmethod
        def NtCreateFile(handle, access, attributes, io_status, *rest):
            oa = attributes._obj
            name = oa.ObjectName.contents
            calls.append(
                (
                    oa.RootDirectory,
                    oa.Attributes,
                    ctypes.wstring_at(name.Buffer, name.Length // 2),
                )
            )
            return ctypes.c_long(0xC0000022 - 2**32).value  # STATUS_ACCESS_DENIED

        @staticmethod
        def RtlNtStatusToDosError(status):
            return 5

    with OwnerOnlyDir(vault) as held:
        advapi32, kernel32, _ = real_api()
        monkeypatch.setattr(winacl, "_api", lambda: (advapi32, kernel32, _NtDll))
        with pytest.raises(OwnerOnlyError, match="NtCreateFile"):
            held.create_file("secret")
        root = held._handle
    assert calls == [(root, winacl._OBJ_CASE_INSENSITIVE | winacl._OBJ_DONT_REPARSE, "secret")]


@windows_only
@pytest.mark.parametrize("name", ["..", "sub\\x", "sub/x", ""])
def test_anchored_operations_take_one_component_only(vault, name):
    with OwnerOnlyDir(vault) as held, pytest.raises(OwnerOnlyError, match="refusing name"):
        held.create_file(name)


@windows_only
def test_a_held_directory_cannot_be_renamed_away(vault):
    with OwnerOnlyDir(vault):
        with pytest.raises(PermissionError):
            os.rename(vault, vault.parent / "moved")


@windows_only
def test_creation_stays_in_the_verified_directory_when_an_ancestor_is_swapped(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    vault = parent / "vault"
    winacl.create_owner_only_dir(vault)
    decoy = tmp_path / "decoy"
    winacl.create_owner_only_dir(decoy)
    winacl.create_owner_only_dir(decoy / "vault")
    with OwnerOnlyDir(vault) as held:
        try:
            os.rename(parent, tmp_path / "parent-moved")
        except PermissionError:
            swapped = False  # Windows refuses: the held directory pins its ancestors
        else:
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(parent), str(decoy)],
                check=True,
                capture_output=True,
            )
            swapped = True
        fd = held.create_file("secret")
        os.close(fd)
    real = (tmp_path / "parent-moved" / "vault") if swapped else vault
    assert (real / "secret").exists()
    assert not (decoy / "vault" / "secret").exists()


@windows_only
def test_a_symlink_to_an_owner_only_file_is_refused(vault):
    _write(vault, "secret", b"x")
    link = vault.parent / "link"
    try:
        os.symlink(vault / "secret", link)
    except OSError:
        pytest.skip("creating symlinks needs Developer Mode or the privilege")
    with pytest.raises(OwnerOnlyError, match="reparse point"):
        winacl.open_owner_only_for_read(link)
