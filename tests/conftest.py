"""Shared fixtures."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from psoperator.common import winacl


class PrivateFiles:
    """Owner-only files and directories made the way the code under test
    makes them, on either platform: mode ``0700``/``0600`` on POSIX, an
    owner-only protected DACL on Windows. The pytest temp folder is not
    owner-only on Windows (it inherits entries for SYSTEM and
    Administrators), so a test that means "a private directory" uses
    :attr:`home` rather than ``tmp_path``."""

    def __init__(self, tmp_path: Path) -> None:
        self.home = self.dir(tmp_path / "home")

    @staticmethod
    def dir(path: Path) -> Path:
        if os.name == "nt":
            winacl.create_owner_only_dir(path)
        else:
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        return path

    @staticmethod
    def write(path: Path, data: bytes | str) -> Path:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if os.name == "nt":
            with winacl.OwnerOnlyDir(path.parent) as held:
                fd = held.create_file(path.name)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
        else:
            path.write_bytes(raw)
            path.chmod(0o600)
        return path

    @staticmethod
    def is_owner_only(path: Path) -> bool:
        if os.name != "nt":
            return stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
        try:
            if path.is_dir():
                winacl.check_owner_only_dir(path)
            else:
                os.close(winacl.open_owner_only_for_read(path))
        except winacl.OwnerOnlyError:
            return False
        return True


@pytest.fixture
def private(tmp_path) -> PrivateFiles:
    return PrivateFiles(tmp_path)
