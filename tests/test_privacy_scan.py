"""The privacy gate (scripts/privacy_scan.py): what it must catch, what it must
let through, and that a commit message is scanned like a file."""

from __future__ import annotations

import importlib.util
import os
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
# files. These run the real hook in a throwaway repository with a fake term,
# in a Git environment isolated from the developer's own configuration.

_TERM = "examplecorp"


class _HookRepo:
    def __init__(self, tmp_path: Path) -> None:
        import shutil

        if shutil.which("python3") is None:
            pytest.skip("the hooks run python3, which is not on PATH")
        self.repo = tmp_path / "repo"
        shutil.copytree(
            _SCRIPT.parent, self.repo / "scripts", ignore=shutil.ignore_patterns("__pycache__")
        )
        self.denylist = tmp_path / "denylist"
        self.denylist.write_text(f"{_TERM}\n")
        empty = tmp_path / "gitconfig"
        empty.write_text("")
        # No inherited GIT_* variable (identity, config, repository) survives,
        # and neither the global nor the system configuration is read.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(
            GIT_CONFIG_GLOBAL=str(empty),
            GIT_CONFIG_NOSYSTEM="1",
            PRIVACY_DENYLIST=str(self.denylist),
        )
        self.git("init", "-q")
        self.git("config", "core.hooksPath", "scripts/hooks")
        self.git("config", "user.name", "Someone")
        self.git("config", "user.email", "someone@users.noreply.github.com")
        (self.repo / "notes.txt").write_text("nothing here\n")
        self.git("add", "-A")

    def git(self, *argv: str, env: dict | None = None, check: bool = True):
        return subprocess.run(
            ["git", "-C", str(self.repo), *argv],
            capture_output=True, text=True, env={**self.env, **(env or {})}, check=check,
        )  # fmt: skip

    def commit(self, *argv: str, env: dict | None = None):
        result = self.git(*argv, "commit", "-q", "-m", "a plain message", env=env, check=False)
        return result, result.stdout + result.stderr

    def committed(self) -> bool:
        return self.git("rev-parse", "-q", "--verify", "HEAD", check=False).returncode == 0


@pytest.fixture
def hook_repo(tmp_path):
    return _HookRepo(tmp_path)


def _refused_for_identity(hook_repo, result, output) -> None:
    assert result.returncode != 0
    assert "commit-identity" in output and "denylist term #1" in output, output
    assert _TERM not in output.lower(), "the refusal echoed the term"
    assert not hook_repo.committed()


def test_a_clean_identity_commits(hook_repo):
    result, output = hook_repo.commit()
    assert result.returncode == 0, output
    assert hook_repo.committed()


def test_a_denylisted_configured_email_is_refused(hook_repo):
    hook_repo.git("config", "user.email", f"me@{_TERM}.test")
    _refused_for_identity(hook_repo, *hook_repo.commit())


def test_a_denylisted_command_scoped_email_is_refused(hook_repo):
    _refused_for_identity(hook_repo, *hook_repo.commit("-c", f"user.email=me@{_TERM}.test"))


@pytest.mark.parametrize("variable", ["GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"])
def test_a_denylisted_email_from_the_environment_is_refused(hook_repo, variable):
    result, output = hook_repo.commit(env={variable: f"me@{_TERM}.test"})
    _refused_for_identity(hook_repo, result, output)


def test_a_denylisted_author_option_is_refused(hook_repo):
    result = hook_repo.git(
        "commit", "-q", "-m", "a plain message", f"--author=Someone <me@{_TERM}.test>",
        check=False,
    )  # fmt: skip
    _refused_for_identity(hook_repo, result, result.stdout + result.stderr)


def test_an_identity_that_cannot_be_resolved_is_refused_without_git_s_message(hook_repo):
    # The hook must fail closed rather than scan empty input, and must not
    # pass on Git's own error, which can carry an inferred address. `git
    # commit` checks the identity before the hook and refuses first, so the
    # hook's own branch is exercised by running it directly.
    import shutil

    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("no POSIX sh on PATH to run the hook directly")
    hook_repo.git("config", "--unset", "user.email")
    hook_repo.git("config", "user.useConfigOnly", "true")
    result = subprocess.run(
        [sh, "scripts/hooks/pre-commit"],
        cwd=hook_repo.repo, capture_output=True, text=True, env=hook_repo.env,
    )  # fmt: skip
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "commit-identity: the author identity could not be resolved" in output, output
    assert "auto-detection" not in output and "@" not in output
    hook_repo.git("config", "user.email", "someone@users.noreply.github.com")
    passed = subprocess.run(
        [sh, "scripts/hooks/pre-commit"],
        cwd=hook_repo.repo, capture_output=True, text=True, env=hook_repo.env,
    )  # fmt: skip
    assert passed.returncode == 0, passed.stdout + passed.stderr  # the control


def test_a_committer_that_cannot_be_resolved_is_refused(hook_repo):
    # The second lookup on its own: the author resolves from the environment,
    # the committer has no email, and the hook still refuses.
    import shutil

    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("no POSIX sh on PATH to run the hook directly")
    hook_repo.git("config", "--unset", "user.email")
    hook_repo.git("config", "user.useConfigOnly", "true")
    result = subprocess.run(
        [sh, "scripts/hooks/pre-commit"],
        cwd=hook_repo.repo, capture_output=True, text=True,
        env={**hook_repo.env, "GIT_AUTHOR_EMAIL": "someone@users.noreply.github.com"},
    )  # fmt: skip
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "commit-identity: the committer identity could not be resolved" in output, output
    assert "auto-detection" not in output


def test_without_a_denylist_only_the_built_in_patterns_apply(hook_repo):
    # The control for the denylist itself: with no denylist file the same
    # identity commits, so the refusals above come from the denylist.
    hook_repo.git("config", "user.email", f"me@{_TERM}.test")
    result, output = hook_repo.commit(env={"PRIVACY_DENYLIST": str(hook_repo.repo / "missing")})
    assert result.returncode == 0, output
    assert hook_repo.committed()


# --- a finding never echoes a denylist term ----------------------------------


def test_a_pattern_match_that_contains_a_term_is_redacted(scan):
    line = f"see /home/{_TERM}/x and 10.1.2.3"  # privacy: example
    findings = scan.scan_lines("notes", [line], [_TERM])
    assert "notes:1: private-lan-address: 10.1.2.3" in findings  # privacy: example
    assert any("home-directory-path: <redacted>" in f for f in findings)
    assert any("denylist term #1" in f for f in findings)
    assert not any(_TERM in f.lower() for f in findings)
    plain = scan.scan_lines("notes", ["see /home/someone/x"], [_TERM])  # privacy: example
    assert plain == ["notes:1: home-directory-path: /home/someone"]  # privacy: example


def test_a_file_name_that_contains_a_term_is_redacted(scan):
    findings = scan.scan_lines(f"docs/{_TERM}.md", [f"{_TERM} host"], [_TERM])
    assert findings == ["<name redacted>:1: denylist term #1"]
