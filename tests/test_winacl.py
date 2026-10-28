"""Windows owner-only verification (D-01).

The policy is pure and pinned on every platform, each rule with a negative
control. The descriptor reading and creation run against real files on
Windows only.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from psoperator.common import winacl
from psoperator.common.winacl import (
    SYSTEM_SID,
    Ace,
    OwnerOnlyError,
    SecurityInfo,
    owner_only_problem,
    owner_only_sddl,
)

USER = "S-1-5-21-1-2-3-1001"
EVERYONE = "S-1-1-0"
ADMINISTRATORS = "S-1-5-32-544"

windows_only = pytest.mark.skipif(os.name != "nt", reason="real Windows descriptors")


def _info(*aces: Ace, owner: str = USER, protected: bool = True) -> SecurityInfo:
    return SecurityInfo(owner, protected, tuple(aces))


def _allow(sid: str, inherited: bool = False) -> Ace:
    return Ace("allow", sid, inherited)


def test_owner_and_system_only_is_owner_only():
    assert owner_only_problem(_info(_allow(USER), _allow(SYSTEM_SID)), USER) is None


def test_a_deny_entry_for_anyone_is_acceptable():
    info = _info(_allow(USER), Ace("deny", EVERYONE, False))
    assert owner_only_problem(info, USER) is None


@pytest.mark.parametrize(
    "info, expected",
    [
        (_info(_allow(USER), owner=ADMINISTRATORS), "owned by"),
        (SecurityInfo(USER, True, None), "null DACL"),
        (_info(_allow(USER), protected=False), "unprotected"),
        (_info(_allow(USER), _allow(SYSTEM_SID, inherited=True)), "inherited"),
        (_info(_allow(USER), _allow(EVERYONE)), f"grants access to {EVERYONE}"),
        (_info(_allow(USER), _allow(ADMINISTRATORS)), f"grants access to {ADMINISTRATORS}"),
        (_info(_allow(USER), Ace("other", "?", False, 0x9)), "unsupported type 0x09"),
    ],
    ids=["wrong-owner", "null-dacl", "unprotected", "inherited", "everyone", "admins", "other"],
)
def test_each_rule_refuses(info, expected):
    problem = owner_only_problem(info, USER)
    assert problem is not None and expected in problem


def test_the_created_descriptor_names_only_the_user_and_system():
    assert owner_only_sddl(USER) == f"O:{USER}D:P(A;;FA;;;{USER})(A;;FA;;;SY)"


@pytest.mark.skipif(os.name == "nt", reason="the non-Windows refusal")
def test_off_windows_every_operation_refuses(tmp_path):
    for call in (
        winacl.current_user_sid,
        lambda: winacl.check_owner_only_dir(tmp_path),
        lambda: winacl.open_owner_only_for_read(tmp_path / "x"),
        lambda: winacl.create_owner_only_file(tmp_path / "x"),
        lambda: winacl.create_owner_only_dir(tmp_path / "d"),
    ):
        with pytest.raises(OwnerOnlyError):
            call()


# --- real descriptors -----------------------------------------------------


def _grant(path, sid: str) -> None:
    subprocess.run(
        ["icacls", str(path), "/grant", f"*{sid}:(R)"],
        check=True,
        capture_output=True,
    )


@windows_only
def test_current_user_sid_is_a_user_sid():
    assert winacl.current_user_sid().startswith("S-1-5-")


@windows_only
def test_a_created_file_is_owner_only_and_reads_back(tmp_path):
    path = tmp_path / "secret"
    fd = winacl.create_owner_only_file(path)
    try:
        os.write(fd, b"material")
    finally:
        os.close(fd)
    fd = winacl.open_owner_only_for_read(path)
    try:
        assert os.read(fd, 100) == b"material"
    finally:
        os.close(fd)


@windows_only
def test_a_created_file_carries_exactly_the_owner_only_descriptor(tmp_path):
    import msvcrt

    path = tmp_path / "secret"
    os.close(winacl.create_owner_only_file(path))
    fd = winacl.open_owner_only_for_read(path)
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
def test_creating_over_an_existing_file_refuses(tmp_path):
    path = tmp_path / "secret"
    os.close(winacl.create_owner_only_file(path))
    with pytest.raises(FileExistsError):
        winacl.create_owner_only_file(path)


@windows_only
def test_a_normally_created_file_is_refused(tmp_path):
    path = tmp_path / "plain"
    path.write_bytes(b"x")
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.open_owner_only_for_read(path)


@windows_only
def test_an_extra_allow_entry_is_refused(tmp_path):
    path = tmp_path / "secret"
    os.close(winacl.create_owner_only_file(path))
    _grant(path, EVERYONE)
    with pytest.raises(OwnerOnlyError, match=f"grants access to {EVERYONE}"):
        winacl.open_owner_only_for_read(path)


@windows_only
def test_a_missing_file_is_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        winacl.open_owner_only_for_read(tmp_path / "missing")


@windows_only
def test_a_directory_is_not_read_as_a_file(tmp_path):
    directory = tmp_path / "d"
    winacl.create_owner_only_dir(directory)
    with pytest.raises(OwnerOnlyError, match="not a regular file"):
        winacl.open_owner_only_for_read(directory)


@windows_only
def test_a_created_directory_is_owner_only(tmp_path):
    directory = tmp_path / "d"
    winacl.create_owner_only_dir(directory)
    winacl.check_owner_only_dir(directory)
    with pytest.raises(FileExistsError):
        winacl.create_owner_only_dir(directory)


@windows_only
def test_a_normally_created_directory_is_refused(tmp_path):
    directory = tmp_path / "plain"
    directory.mkdir()
    with pytest.raises(OwnerOnlyError, match="not owner-only"):
        winacl.check_owner_only_dir(directory)


@windows_only
def test_an_extra_allow_entry_on_a_directory_is_refused(tmp_path):
    directory = tmp_path / "d"
    winacl.create_owner_only_dir(directory)
    _grant(directory, EVERYONE)
    with pytest.raises(OwnerOnlyError, match=f"grants access to {EVERYONE}"):
        winacl.check_owner_only_dir(directory)


@windows_only
def test_a_symlink_to_an_owner_only_file_is_refused(tmp_path):
    target = tmp_path / "secret"
    os.close(winacl.create_owner_only_file(target))
    link = tmp_path / "link"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("creating symlinks needs Developer Mode or the privilege")
    with pytest.raises(OwnerOnlyError, match="reparse point"):
        winacl.open_owner_only_for_read(link)
