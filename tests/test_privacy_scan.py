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


@pytest.mark.parametrize(
    "line",
    [
        r"C:\Users\someone\ai",  # privacy: example
        "c:/Users/someone/ai",  # privacy: example
        r"D:\Documents and Settings\someone",  # privacy: example
    ],
)
def test_windows_home_paths_are_caught(scan, line):
    # strip the marker: the line must be caught on its own
    assert scan.scan_lines("f", [line.split("  #")[0]], [])


def test_the_example_marker_never_exempts_a_denylist_term(scan):
    line = "host-a 10.20.30.40  # privacy: example"
    assert scan.scan_lines("f", [line], ["host-a"]) == ["f:1: denylist term #1"]


def test_undecodable_files_are_scanned_not_skipped(scan, tmp_path):
    git = ["git", "-C", str(tmp_path)]
    subprocess.run([*git, "init", "-q"], check=True)
    (tmp_path / "utf16.txt").write_bytes("route 10.20.30.40\n".encode("utf-16"))  # privacy: example
    (tmp_path / "latin1.txt").write_bytes(b"\xe9 host-a\n")
    subprocess.run([*git, "add", "-A"], check=True)
    findings = scan.scan_files(tmp_path, ["host-a"])
    assert any(f.startswith("utf16.txt:1: private-lan-address") for f in findings)
    assert "latin1.txt:1: denylist term #1" in findings


def test_staged_mode_scans_the_index_not_the_working_tree(tmp_path):
    git = ["git", "-C", str(tmp_path)]
    subprocess.run([*git, "init", "-q"], check=True)
    f = tmp_path / "notes.txt"
    f.write_text("route 10.20.30.40\n")  # privacy: example
    subprocess.run([*git, "add", "notes.txt"], check=True)
    f.write_text("nothing here\n")  # edited out of the file, but still staged
    staged = _run("staged", "--root", str(tmp_path))
    assert staged.returncode == 1 and "notes.txt:1: private-lan-address" in staged.stdout
    assert _run("files", "--root", str(tmp_path)).returncode == 0  # the tree alone looks clean
    subprocess.run([*git, "add", "notes.txt"], check=True)
    assert _run("staged", "--root", str(tmp_path)).returncode == 0


# --- the pre-commit hook refuses a denylisted identity ----------------------
# An author or committer email is published with the commit as surely as its
# files. These run the real hook in a throwaway repository with a fake term.

_TERM = "examplecorp"


def _hook_repo(tmp_path):
    import shutil

    if shutil.which("python3") is None:
        pytest.skip("the hooks run python3, which is not on PATH")
    repo = tmp_path / "repo"
    shutil.copytree(_SCRIPT.parent, repo / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    denylist = tmp_path / "denylist"
    denylist.write_text(f"{_TERM}\n")
    git = ["git", "-C", str(repo)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "config", "core.hooksPath", "scripts/hooks"], check=True)
    subprocess.run([*git, "config", "user.name", "Someone"], check=True)
    subprocess.run([*git, "config", "user.email", "someone@users.noreply.github.com"], check=True)
    (repo / "notes.txt").write_text("nothing here\n")
    subprocess.run([*git, "add", "-A"], check=True)
    return repo, git, denylist


def _commit(git, denylist, *extra, env_extra=None):
    import os

    env = {**os.environ, "PRIVACY_DENYLIST": str(denylist), **(env_extra or {})}
    for name in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
        if not env_extra or name not in env_extra:
            env.pop(name, None)
    return subprocess.run(
        [*git, "commit", "-q", "-m", "a plain message", *extra],
        capture_output=True, text=True, env=env,
    )  # fmt: skip


def _committed(git) -> bool:
    return (
        subprocess.run(
            [*git, "rev-parse", "-q", "--verify", "HEAD"], capture_output=True
        ).returncode
        == 0
    )


def test_a_clean_identity_commits(tmp_path):
    repo, git, denylist = _hook_repo(tmp_path)
    result = _commit(git, denylist)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _committed(git)


def test_a_denylisted_configured_email_is_refused(tmp_path):
    repo, git, denylist = _hook_repo(tmp_path)
    subprocess.run([*git, "config", "user.email", f"me@{_TERM}.test"], check=True)
    result = _commit(git, denylist)
    assert result.returncode != 0
    assert "commit-identity" in result.stdout + result.stderr
    assert _TERM not in result.stdout + result.stderr, "the finding echoed the term"
    assert not _committed(git)


@pytest.mark.parametrize("variable", ["GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"])
def test_a_denylisted_email_from_the_environment_is_refused(tmp_path, variable):
    repo, git, denylist = _hook_repo(tmp_path)
    result = _commit(git, denylist, env_extra={variable: f"me@{_TERM}.test"})
    assert result.returncode != 0
    assert not _committed(git)


def test_a_denylisted_author_option_is_refused(tmp_path):
    repo, git, denylist = _hook_repo(tmp_path)
    result = _commit(git, denylist, f"--author=Someone <me@{_TERM}.test>")
    assert result.returncode != 0
    assert not _committed(git)
