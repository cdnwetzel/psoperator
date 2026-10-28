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


# --- trusted-parent policy ------------------------------------------------------

FULL = 0x001F01FF  # FILE_ALL_ACCESS
READ_EXECUTE = 0x001200A9
USERS = "S-1-5-32-545"
AUTHENTICATED_USERS = "S-1-5-11"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"


def _grant_ace(sid: str, mask: int, *, inherited: bool = False, inherit_only: bool = False) -> Ace:
    return Ace("allow", sid, inherited, 0, mask, inherit_only)


def _profile_like(*extra: Ace, owner: str = USER) -> SecurityInfo:
    """A profile or project folder: inherited full control for SYSTEM,
    Administrators and the user, unprotected."""
    aces = tuple(_grant_ace(s, FULL, inherited=True) for s in (SYSTEM_SID, ADMINISTRATORS, USER))
    return SecurityInfo(owner, False, aces + extra)


@pytest.mark.parametrize(
    "info",
    [
        _profile_like(),
        _profile_like(owner=SYSTEM_SID),
        _profile_like(owner=ADMINISTRATORS),
        _profile_like(_grant_ace(OWNER_RIGHTS, FULL)),
        _profile_like(_grant_ace(EVERYONE, READ_EXECUTE)),
        _profile_like(_grant_ace(AUTHENTICATED_USERS, FULL, inherit_only=True)),
        _profile_like(Ace("deny", EVERYONE, False, 1, FULL)),
        _profile_like(Ace("other", "?", False, 0x9, FULL, True)),
        _info(_allow(USER), _allow(SYSTEM_SID)),
    ],
    ids=[
        "profile",
        "owned-by-system",
        "owned-by-admins",
        "owner-rights",
        "everyone-reads",
        "inherit-only-write",
        "deny",
        "inherit-only-unsupported",
        "owner-only",
    ],
)
def test_a_parent_only_trusted_accounts_can_change_is_trusted(info):
    assert winacl.trusted_parent_problem(info, USER) is None


@pytest.mark.parametrize(
    "bit",
    [0x2, 0x4, 0x40, 0x00010000, 0x00040000, 0x00080000, 0x02000000, 0x10000000, 0x40000000],
    ids=[
        "add-file",
        "add-subdirectory",
        "delete-child",
        "delete",
        "write-dac",
        "write-owner",
        "maximum-allowed",
        "generic-all",
        "generic-write",
    ],
)
def test_each_right_that_changes_entries_makes_a_parent_untrusted(bit):
    problem = winacl.trusted_parent_problem(_profile_like(_grant_ace(USERS, bit)), USER)
    assert problem is not None and f"lets {USERS} change its entries" in problem


@pytest.mark.parametrize(
    "info, expected",
    [
        (_profile_like(owner=TRUSTED_INSTALLER), "owned by"),
        (_profile_like(owner=EVERYONE), "owned by"),
        (SecurityInfo(USER, False, None), "null DACL"),
        (_profile_like(_grant_ace(AUTHENTICATED_USERS, 0x4)), "change its entries"),
        (_profile_like(_grant_ace(EVERYONE, FULL, inherited=True)), "change its entries"),
        (_profile_like(_grant_ace(CREATOR_OWNER, FULL)), "change its entries"),
        (_profile_like(Ace("other", "?", False, 0x5, FULL)), "unsupported type 0x05"),
    ],
    ids=[
        "trusted-installer",
        "everyone-owns",
        "null-dacl",
        "drive-root-style",
        "inherited-everyone",
        "creator-owner-applies",
        "object-ace",
    ],
)
def test_each_trusted_parent_rule_refuses(info, expected):
    problem = winacl.trusted_parent_problem(info, USER)
    assert problem is not None and expected in problem


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
def test_current_user_sid_is_the_token_user(vault):
    # Any SID form: a local or domain account is S-1-5-21-..., an Entra ID
    # account S-1-12-1-.... Checked against whoami, an independent reader of
    # the token, and against the owner of a file this process created.
    import msvcrt

    sid = winacl.current_user_sid()
    assert sid.startswith("S-1-")
    line = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], check=True, capture_output=True, text=True
    ).stdout.strip()
    assert line.rsplit(",", 1)[1].strip('"') == sid
    _write(vault, "mine", b"x")
    fd = winacl.open_owner_only_for_read(vault / "mine")
    try:
        assert winacl.security_of_handle(msvcrt.get_osfhandle(fd)).owner_sid == sid
    finally:
        os.close(fd)


@windows_only
def test_a_null_dacl_is_parsed_as_null_and_refused(vault):
    # Parser-level control: a real null DACL, not a hand-built SecurityInfo.
    _set_dacl(vault, "D:NO_ACCESS_CONTROL")
    _, kernel32, _ = winacl._api()
    handle = winacl._open_no_follow(kernel32, vault, winacl._READ_CONTROL, 0x7)
    try:
        assert winacl.security_of_handle(handle).aces is None
    finally:
        kernel32.CloseHandle(handle)
    with pytest.raises(OwnerOnlyError, match="null DACL"):
        winacl.check_owner_only_dir(vault)
    with pytest.raises(OwnerOnlyError, match="null DACL"):
        winacl.check_trusted_parent(vault)


@windows_only
def test_a_verified_read_is_refused_while_a_writer_is_open(vault):
    # The reader shares read only, so it never reads a file another handle can
    # be writing, and no writer can open while it reads.
    _write(vault, "secret", b"x")
    with open(vault / "secret", "ab"):
        with pytest.raises(OwnerOnlyError, match="cannot open"):
            winacl.open_owner_only_for_read(vault / "secret")
    fd = winacl.open_owner_only_for_read(vault / "secret")  # the control
    try:
        with pytest.raises(PermissionError):
            open(vault / "secret", "ab")
    finally:
        os.close(fd)


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


# --- parents, replacement and removal (Windows) --------------------------------


def _icacls_grant(path, grant: str) -> None:
    subprocess.run(["icacls", str(path), "/grant", grant], check=True, capture_output=True)


@windows_only
def test_ace_masks_and_inherit_only_flags_are_read(vault):
    user = winacl.current_user_sid()
    _set_dacl(vault, f"D:P(A;;FA;;;{user})(A;;0x4;;;WD)(A;OICIIO;GA;;;AU)")
    _, kernel32, _ = winacl._api()
    handle = winacl._open_no_follow(kernel32, vault, winacl._READ_CONTROL, 0x7)
    try:
        info = winacl.security_of_handle(handle)
    finally:
        kernel32.CloseHandle(handle)
    entries = {(a.sid, a.mask, a.inherit_only) for a in info.aces}
    assert (EVERYONE, 0x4, False) in entries
    assert (AUTHENTICATED_USERS, 0x10000000, True) in entries
    assert (user, FULL, False) in entries


@windows_only
def test_the_temp_folder_and_an_owner_only_directory_are_trusted_parents(tmp_path, vault):
    winacl.check_trusted_parent(tmp_path)
    winacl.check_trusted_parent(vault)


@windows_only
def test_a_parent_others_can_add_to_is_not_trusted(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    winacl.check_trusted_parent(shared)  # the control: inherited entries only
    _icacls_grant(shared, f"*{USERS}:(AD)")
    with pytest.raises(OwnerOnlyError, match=f"lets {USERS} change its entries"):
        winacl.check_trusted_parent(shared)


@windows_only
def test_a_parent_others_can_only_read_is_trusted(tmp_path):
    readable = tmp_path / "readable"
    readable.mkdir()
    _icacls_grant(readable, f"*{USERS}:(RX)")
    winacl.check_trusted_parent(readable)


@windows_only
def test_a_trusted_parent_must_be_an_existing_directory(tmp_path):
    (tmp_path / "file").write_bytes(b"x")
    with pytest.raises(OwnerOnlyError, match="not a directory"):
        winacl.check_trusted_parent(tmp_path / "file")
    with pytest.raises(FileNotFoundError):
        winacl.check_trusted_parent(tmp_path / "missing")


@windows_only
def test_a_junction_is_not_a_trusted_parent(tmp_path, vault):
    junction = tmp_path / "junction"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(vault)], check=True, capture_output=True
    )
    with pytest.raises(OwnerOnlyError, match="reparse point"):
        winacl.check_trusted_parent(junction)


@windows_only
def test_missing_components_are_created_owner_only(tmp_path):
    target = tmp_path / "a" / "b" / "c"
    with winacl.ensure_owner_only_dir(target) as held:
        assert held.path == target
        os.close(held.create_file("x"))
    for part in (tmp_path / "a", tmp_path / "a" / "b", target):
        winacl.check_owner_only_dir(part)
    with winacl.ensure_owner_only_dir(target) as held:  # all present: just held
        assert held.path == target


@windows_only
def test_an_existing_trusted_parent_is_left_as_it_is(tmp_path):
    (tmp_path / "plain").mkdir()
    with winacl.ensure_owner_only_dir(tmp_path / "plain" / "private"):
        pass
    winacl.check_owner_only_dir(tmp_path / "plain" / "private")
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.check_owner_only_dir(tmp_path / "plain")


@windows_only
def test_nothing_is_created_under_a_parent_others_can_change(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    _icacls_grant(shared, f"*{USERS}:(AD)")
    with pytest.raises(OwnerOnlyError, match="not a safe parent"):
        winacl.ensure_owner_only_dir(shared / "a" / "b")
    assert list(shared.iterdir()) == []


@windows_only
def test_an_existing_target_must_be_owner_only(tmp_path):
    (tmp_path / "plain").mkdir()
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.ensure_owner_only_dir(tmp_path / "plain")


@windows_only
def test_a_component_that_appears_meanwhile_must_be_owner_only(tmp_path, monkeypatch):
    # Someone makes the next component, with an ordinary DACL, between the
    # check and the create: the create reports it exists and the anchored
    # open refuses it rather than descending into it.
    def _raced(self, name):
        (self.path / name).mkdir()
        raise FileExistsError(name)

    monkeypatch.setattr(OwnerOnlyDir, "create_dir", _raced)
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.ensure_owner_only_dir(tmp_path / "a" / "b")
    assert not (tmp_path / "a" / "b").exists()


@windows_only
def test_creation_is_anchored_to_each_held_parent(tmp_path, monkeypatch):
    # Deterministic: every missing component is created and then opened
    # relative to the handle on the component before it, never by path.
    calls = []
    real_open = OwnerOnlyDir._nt_open

    def _recording(self, name, access, disposition, options, descriptor, share=None):
        calls.append((self.path, self._handle, name, disposition))
        return real_open(self, name, access, disposition, options, descriptor, share)

    def _no_path_create(path):
        raise AssertionError(f"created by path: {path}")

    monkeypatch.setattr(OwnerOnlyDir, "_nt_open", _recording)
    monkeypatch.setattr(winacl, "create_owner_only_dir", _no_path_create)
    with winacl.ensure_owner_only_dir(tmp_path / "a" / "b") as held:
        final = held.path
    create, open_ = winacl._FILE_CREATE, winacl._FILE_OPEN
    assert [(path, name, disposition) for path, _, name, disposition in calls] == [
        (tmp_path, "a", create),
        (tmp_path, "a", open_),
        (tmp_path / "a", "b", create),
        (tmp_path / "a", "b", open_),
    ]
    assert all(handle is not None for _, handle, _, _ in calls)
    assert calls[0][1] == calls[1][1] and calls[2][1] == calls[3][1] != calls[0][1]
    assert final == tmp_path / "a" / "b"


@windows_only
def test_open_dir_refuses_what_is_not_owner_only(vault):
    (vault / "plain").mkdir()
    with OwnerOnlyDir(vault) as held:
        with pytest.raises(OwnerOnlyError, match="not owner-only"):
            held.open_dir("plain")
        with pytest.raises(FileNotFoundError):
            held.open_dir("missing")
        with pytest.raises(OwnerOnlyError, match="refusing name"):
            held.open_dir("..")


def _read(directory: Path, name: str) -> bytes:
    with OwnerOnlyDir(directory) as held:
        fd = held.open_file(name)
    try:
        return os.read(fd, 100)
    finally:
        os.close(fd)


def _replace(directory: Path, name: str, data: bytes) -> None:
    with OwnerOnlyDir(directory) as held:
        fd = held.create_file(f"{name}.tmp")
        try:
            os.write(fd, data)
            held.replace(fd, name)
        finally:
            os.close(fd)


@windows_only
def test_replace_renames_over_the_old_file_and_stays_owner_only(vault):
    _write(vault, "state", b"old")
    _replace(vault, "state", b"new")
    assert _read(vault, "state") == b"new"
    assert sorted(p.name for p in vault.iterdir()) == ["state"]
    _replace(vault, "fresh", b"first")  # and with no file to replace
    assert _read(vault, "fresh") == b"first"


@windows_only
@pytest.mark.parametrize("name", ["state", "état", "a\U0001f600b"], ids=["ascii", "bmp", "astral"])
def test_the_rename_buffer_holds_the_whole_utf16_name(vault, name):
    # The name is passed as UTF-16 with an explicit byte length. Sizing the
    # buffer by code points left an astral name short of its length.
    information = winacl._rename_information(0, name)
    raw = bytes(information.FileName)
    assert information.FileNameLength == len(raw) == len(name.encode("utf-16-le"))
    assert raw.decode("utf-16-le") == name
    _replace(vault, name, b"x")
    assert sorted(p.name for p in vault.iterdir()) == [name]


@windows_only
@pytest.mark.parametrize("name", ["..", "sub\\x", "sub/x", "", "state:stream"])
def test_replace_takes_one_component_only(vault, name):
    with OwnerOnlyDir(vault) as held:
        fd = held.create_file("new.tmp")
        try:
            with pytest.raises(OwnerOnlyError, match="refusing name"):
                held.replace(fd, name)
        finally:
            os.close(fd)


@windows_only
def test_replace_passes_the_held_handle_as_root(vault, monkeypatch):
    # Deterministic, like the creation test: the rename target must be
    # resolved relative to the held handle, never by path.
    calls = []
    real_api = winacl._api

    class _NtDll:
        @staticmethod
        def NtSetInformationFile(handle, io_status, information, length, klass):
            info = information._obj
            name = bytes(info.FileName)[: info.FileNameLength].decode("utf-16-le")
            calls.append((info.RootDirectory, info.ReplaceIfExists, name, klass))
            return ctypes.c_long(0xC0000022 - 2**32).value  # STATUS_ACCESS_DENIED

        @staticmethod
        def RtlNtStatusToDosError(status):
            return 5

    with OwnerOnlyDir(vault) as held:
        fd = held.create_file("new.tmp")
        try:
            advapi32, kernel32, _ = real_api()
            monkeypatch.setattr(winacl, "_api", lambda: (advapi32, kernel32, _NtDll))
            with pytest.raises(OwnerOnlyError, match="renaming"):
                held.replace(fd, "state")
            root = held._handle
        finally:
            monkeypatch.undo()
            os.close(fd)
    assert calls == [(root, 1, "state", 10)]


def _open_by_path(vault: Path) -> int:
    return winacl.open_owner_only_for_read(vault / "state")


def _open_anchored(vault: Path) -> int:
    with OwnerOnlyDir(vault) as held:
        return held.open_file("state")


@windows_only
@pytest.mark.parametrize("opener", [_open_by_path, _open_anchored], ids=["by-path", "anchored"])
def test_replace_fails_closed_while_a_handle_is_retained_on_the_old_file(vault, opener):
    # Renaming over an open file is refused, even when the reader shares
    # delete, so a retained handle never sees its file swapped underneath it:
    # the replace fails, the old file and the retained read are untouched,
    # and the same replace succeeds once the handle is closed.
    _write(vault, "state", b"old")
    retained = opener(vault)
    try:
        with OwnerOnlyDir(vault) as held:
            fd = held.create_file("state.tmp")
            try:
                os.write(fd, b"new")
                with pytest.raises(OwnerOnlyError, match="renaming"):
                    held.replace(fd, "state")
                assert os.read(retained, 100) == b"old"
                os.close(retained)
                retained = None
                held.replace(fd, "state")
            finally:
                os.close(fd)
    finally:
        if retained is not None:
            os.close(retained)
    assert _read(vault, "state") == b"new"


@windows_only
def test_a_hard_link_carries_the_file_descriptor_not_its_own(tmp_path, vault):
    # The descriptor belongs to the file, so a second name cannot widen or
    # narrow it: a link to an owner-only file reads as owner-only from
    # anywhere, and a link in the vault to a loose file is refused.
    _write(vault, "secret", b"x")
    os.link(vault / "secret", tmp_path / "elsewhere")
    fd = winacl.open_owner_only_for_read(tmp_path / "elsewhere")
    os.close(fd)

    loose = tmp_path / "loose"
    loose.write_bytes(b"planted")
    os.link(loose, vault / "planted")
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.open_owner_only_for_read(vault / "planted")
    with OwnerOnlyDir(vault) as held, pytest.raises(OwnerOnlyError, match="not owner-only"):
        held.open_file("planted")


@windows_only
def test_unlink_removes_one_file(vault):
    _write(vault, "junk", b"x")
    with OwnerOnlyDir(vault) as held:
        held.unlink("junk")
        with pytest.raises(FileNotFoundError):
            held.unlink("junk")
        held.create_dir("sub")
        with pytest.raises(OwnerOnlyError):
            held.unlink("sub")
        with pytest.raises(OwnerOnlyError, match="refusing name"):
            held.unlink("..")
    assert sorted(p.name for p in vault.iterdir()) == ["sub"]


@windows_only
def test_unlink_removes_a_symlink_not_its_target(vault):
    _write(vault, "secret", b"x")
    try:
        os.symlink(vault / "secret", vault / "link")
    except OSError:
        pytest.skip("creating symlinks needs Developer Mode or the privilege")
    with OwnerOnlyDir(vault) as held:
        held.unlink("link")
    assert sorted(p.name for p in vault.iterdir()) == ["secret"]


class _Kernel32:
    """The real kernel32, with FlushFileBuffers and CloseHandle recorded."""

    def __init__(self, real, flush_ok: bool) -> None:
        self._real, self._flush_ok = real, flush_ok
        self.flushed: list[int] = []
        self.closed: list[int] = []

    def __getattr__(self, name):
        return getattr(self._real, name)

    def FlushFileBuffers(self, handle):
        self.flushed.append(handle)
        if not self._flush_ok:
            ctypes.set_last_error(5)
            return 0
        return self._real.FlushFileBuffers(handle)

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return self._real.CloseHandle(handle)


@windows_only
@pytest.mark.parametrize("flush_ok", [True, False], ids=["flushes", "flush-fails"])
def test_sync_calls_the_flush_and_closes_its_handle(vault, monkeypatch, flush_ok):
    # Removing FlushFileBuffers, or ignoring its failure, fails here: the
    # success path must call it on a handle of its own (not the held one), a
    # failure must raise, and the flush handle is closed either way.
    real_api = winacl._api
    advapi32, kernel32, ntdll = real_api()
    recorder = _Kernel32(kernel32, flush_ok)
    with OwnerOnlyDir(vault) as held:
        monkeypatch.setattr(winacl, "_api", lambda: (advapi32, recorder, ntdll))
        if flush_ok:
            held.sync()
        else:
            with pytest.raises(OwnerOnlyError, match="flushing"):
                held.sync()
        root = held._handle
        monkeypatch.undo()
    assert len(recorder.flushed) == 1
    assert recorder.flushed[0] != root
    assert recorder.closed == recorder.flushed


@windows_only
def test_sync_flushes_the_held_directory(vault):
    with OwnerOnlyDir(vault) as held:
        held.sync()
        held.close()
        with pytest.raises(OwnerOnlyError, match="closed"):
            held.sync()


@windows_only
def test_sync_reopens_the_held_handle_itself(vault, monkeypatch):
    # Deterministic: the flush re-opens the held directory relative to its own
    # handle (an empty name), never by path.
    calls = []
    real_api = winacl._api

    class _NtDll:
        @staticmethod
        def NtCreateFile(handle, access, attributes, io_status, *rest):
            oa = attributes._obj
            name = oa.ObjectName.contents
            calls.append((oa.RootDirectory, ctypes.wstring_at(name.Buffer, name.Length // 2)))
            return ctypes.c_long(0xC0000022 - 2**32).value  # STATUS_ACCESS_DENIED

        @staticmethod
        def RtlNtStatusToDosError(status):
            return 5

    with OwnerOnlyDir(vault) as held:
        advapi32, kernel32, _ = real_api()
        monkeypatch.setattr(winacl, "_api", lambda: (advapi32, kernel32, _NtDll))
        with pytest.raises(OwnerOnlyError, match="NtCreateFile"):
            held.sync()
        root = held._handle
        monkeypatch.undo()
    assert calls == [(root, "")]
