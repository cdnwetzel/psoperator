"""The privacy gate (scripts/privacy_scan.py): what it must catch, what it must
let through, and that a commit message is scanned like a file."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "privacy_scan.py"


@pytest.fixture(scope="module")
def scan():
    spec = importlib.util.spec_from_file_location("privacy_scan", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    "line",
    [
        "planner at 10.20.30.40:8003",  # privacy: example
        "router 172.20.0.9",  # privacy: example
        "laptop 192.168.50.60",  # privacy: example
        "172.31.255.1 is still private",  # privacy: example
        "cache under /Users/someone/ai",  # privacy: example
        "clone in /home/someone/ai/psoperator",  # privacy: example
    ],
)
def test_private_values_are_caught(scan, line):
    assert scan.scan_lines("f", [line], [])


@pytest.mark.parametrize(
    "line",
    [
        "documentation range 192.0.2.125 and 203.0.113.10",
        "public resolver 8.8.8.8",
        "172.15.0.1 and 172.32.0.1 are not private",
        "version 10.0.1 and 1.10.0.4.2",  # three-part version; five-part is not an address
        "loopback 127.0.0.1:8000",
        "CI home /home/runner/work",
        "a test value 10.0.0.5  # privacy: example",
    ],
)
def test_public_and_marked_values_pass(scan, line):
    assert scan.scan_lines("f", [line], []) == []


def test_denylist_terms_match_without_echoing_the_term(scan):
    findings = scan.scan_lines("msg", ["deployed on Secret-Host-7"], ["secret-host-7"])
    assert findings == ["msg:1: denylist term #1"]
    assert "secret" not in findings[0].lower()


def test_denylist_file_ignores_comments_and_blanks(scan, tmp_path):
    deny = tmp_path / "deny"
    deny.write_text("# a comment\n\nhost-a\n")
    assert scan.load_denylist(str(deny)) == ["host-a"]
    assert scan.load_denylist(str(tmp_path / "missing")) == []
    assert scan.load_denylist(None) == []


def _run(*argv, stdin="", cwd=None):
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *argv],
        input=stdin, capture_output=True, text=True, cwd=cwd,
    )  # fmt: skip


def test_a_commit_message_is_scanned_like_a_file():
    leak_line = "map 10.20.30.40 -> 192.0.2.40\n"  # privacy: example
    leak = _run("text", "--name", "commit", stdin=leak_line)
    assert leak.returncode == 1 and "commit:1: private-lan-address: 10.20" in leak.stdout
    assert _run("text", stdin="fix the gatekeeper\n").returncode == 0


def test_files_mode_scans_tracked_files_only(tmp_path):
    git = ["git", "-C", str(tmp_path)]
    subprocess.run([*git, "init", "-q"], check=True)
    (tmp_path / "ok.txt").write_text("203.0.113.10\n")
    (tmp_path / "untracked.txt").write_text("10.20.30.40\n")  # privacy: example
    subprocess.run([*git, "add", "ok.txt"], check=True)
    assert _run("files", "--root", str(tmp_path)).returncode == 0
    subprocess.run([*git, "add", "untracked.txt"], check=True)
    result = _run("files", "--root", str(tmp_path))
    assert result.returncode == 1 and "untracked.txt:1" in result.stdout


def test_this_repository_is_clean():
    root = _SCRIPT.parent.parent
    result = _run("files", "--root", str(root))
    assert result.returncode == 0, result.stdout
