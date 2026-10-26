"""The kill-switch path must be absolute wherever it crosses a process boundary.

The gatekeeper service and an operator's shell run in different working
directories. With a relative path, ``psoperator kill`` engages a stop file the
service never reads, and ``kill-drill`` passes against that same wrong file. The
CLI commands and the service therefore refuse a relative path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from psoperator.cli import _run_gatekeeper, main
from psoperator.config import load_config


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    # Isolate from any .env in the caller's working directory.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PSOPERATOR_KILL_SWITCH_PATH", raising=False)
    return tmp_path


@pytest.mark.parametrize("command", ["kill", "resume", "kill-drill"])
def test_cli_refuses_a_relative_kill_switch_path(workdir, monkeypatch, capsys, command):
    monkeypatch.setenv("PSOPERATOR_KILL_SWITCH_PATH", ".psoperator/STOP")
    assert main([command]) == 2
    assert "PSOPERATOR_KILL_SWITCH_PATH" in capsys.readouterr().err
    assert not (workdir / ".psoperator").exists()


def test_cli_refuses_the_relative_default(workdir, capsys):
    assert main(["kill"]) == 2
    assert "is relative" in capsys.readouterr().err
    assert not (workdir / ".psoperator").exists()


def test_cli_refuses_an_unexpanded_home_path(workdir, monkeypatch, capsys):
    monkeypatch.setenv("PSOPERATOR_KILL_SWITCH_PATH", "~/STOP")
    assert main(["kill"]) == 2
    assert "is relative" in capsys.readouterr().err


def test_kill_and_resume_use_and_print_the_absolute_path(workdir, monkeypatch, capsys):
    stop = workdir / "state" / "STOP"
    monkeypatch.setenv("PSOPERATOR_KILL_SWITCH_PATH", str(stop))

    assert main(["kill"]) == 0
    assert stop.is_file()
    assert f"kill switch engaged: {stop}" in capsys.readouterr().out

    assert main(["resume"]) == 0
    assert not stop.exists()
    assert f"kill switch disengaged: {stop}" in capsys.readouterr().out


def test_kill_drill_runs_against_the_absolute_path(workdir, monkeypatch, capsys):
    stop = workdir / "state" / "STOP"
    monkeypatch.setenv("PSOPERATOR_KILL_SWITCH_PATH", str(stop))
    monkeypatch.setenv("PSOPERATOR_AUDIT_LOG_PATH", str(workdir / "audit.jsonl"))

    assert main(["kill-drill"]) == 0
    assert f"at {stop}" in capsys.readouterr().out
    assert not stop.exists()  # the drill lifts only the stop it created


def test_gatekeeper_service_refuses_a_relative_kill_switch_path(workdir, capsys):
    config = load_config(
        kill_switch_path=Path(".psoperator/STOP"),
        ipc_secret_path=workdir / "ipc.secret",
    )
    assert _run_gatekeeper(config) == 1
    assert "PSOPERATOR_KILL_SWITCH_PATH" in capsys.readouterr().err
    # Refused before any service state is created.
    assert not (workdir / "ipc.secret").exists()
