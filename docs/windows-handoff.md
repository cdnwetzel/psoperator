# Windows endpoint handoff

For the operator and for a coding agent (Claude Code) working on the Windows
test endpoint described in `docs/pilot-charter.md`. An agent there starts with
only this repository, so everything it must know is here or linked from here.

## 1. Machine setup (from the management host, over SSH)

The endpoint runs OpenSSH Server, with key-based access for an admin account.
Install machine-wide, and check each version afterwards:

| tool | why | check |
| --- | --- | --- |
| Git for Windows | clone, hooks; its Git Bash is the shell Claude Code uses | `git --version` |
| Python 3.12 | PSOperator | `py -3.12 --version` |
| Node.js LTS | Claude Code and the Codex CLI | `node --version` |
| GitHub CLI | PRs and CI checks | `gh --version` |
| Claude Code | the coding agent | `claude --version` |
| Codex CLI | independent review | `codex --version` |

`winget` is unreliable inside SSH sessions; use the vendors' installers where
it fails.

An SSH session cannot see the logged-in desktop. Nothing that reads or drives
the screen (the probe, the observer, the executor) is run over SSH.

## 2. Desktop session setup (as the user who will run the agent)

1. GitHub access over SSH for the repository owner's account, with one
   `git push` updating both remotes, as on the other machines.
2. Clone this repository, then enable the privacy hooks:
   `git config core.hooksPath scripts/hooks`.
3. Copy the private denylist to `%USERPROFILE%\.config\pxx\public-denylist` by
   hand. It never goes through git. Without it, the hooks cannot catch real
   hostnames.
4. Create a virtual environment and install:
   `py -3.12 -m venv .venv`, then
   `.venv\Scripts\python -m pip install -e ".[dev,a11y,perception]"`.
5. Baseline: `.venv\Scripts\python -m pytest -q` passes, and
   `ruff check psoperator tests scripts` is clean.
6. Sign in to Claude Code, `gh auth login`, and the Codex CLI.
7. Open the target application on this desktop, with a synthetic test record
   loaded.

## 3. Working rules

These are the operator's standing rules. They apply to every change.

- **Updates:** short and frequent.
- **Nothing private, anywhere** (`CONTRIBUTING.md`). Do not name the
  application, its records, the endpoint, or the organisation in files, commit
  messages, PR titles or PR bodies. Scan commit messages and PR text with
  `scripts/privacy_scan.py text --name X < file`, and run a negative control
  that must fail (a fake private address). Empty output is not proof of a
  clean scan.
- **Never commit probe output** or screenshots. They hold on-screen text. Keep
  them outside the clone.
- **Every gate needs a negative control:** a test that fails when the
  protection is removed.
- **Review:** another agent that did not write the change reviews it (for
  example the Codex CLI when Claude wrote it). CodeRabbit is welcome when
  available, not required. Verify every finding against the code.
- **CI on every push:** after each push, wait for CI on that exact commit and
  read the result. A local pass is not a CI pass.
- **Merge:** squash, pinned to the reviewed head, only after the reviewer
  approves and CI passes on that head, and only with the operator's standing
  approval. Afterwards, confirm CI on `main`.
- **No input to the application** until the operator approves that step.
- **Keep docs current:** the charter and roadmap change in the same PR as the
  state they describe.

## 4. Step 1: read-only UI Automation probe

Goal: decide whether the application's UI Automation tree is good enough for
element-bound actions. **No clicks, no typing.**

With a test record open, from the desktop session:

1. **Find the window.** List the top-level windows through pywinauto
   (`Desktop(backend="uia").windows()`): title, process, class.
2. **Run PSOperator's own path.** Build a snapshot with
   `SnapshotBuilder(a11y=WinAutoA11y(), ocr=NullOCR())` from an `MSSCapture`
   frame, and count elements by role. This exercises the backend the services
   will use. `WinAutoA11y` has never been run on Windows, so a fix may be
   needed; make it test-first.
3. **Check what the elements carry.** Do the record's fields and the main
   buttons appear, with usable names? Note that `WinAutoA11y` uses
   `window_text()` as the name, which for an edit box can be its contents.
   Record whether controls have automation ids, which the charter's
   no-record-data audit needs.
4. **Check the coordinates.** Do element bounds line up with the screenshot
   under the display's scaling, and with more than one monitor if present?
5. **Time the walk.** How long does one snapshot take?

**Report**, in the PR that records the result: counts by role, whether names and
automation ids exist, coordinate agreement, timing, and any backend fix. No
on-screen text. Then update `docs/pilot-charter.md` with the verdict: go, go
with OCR, or a fixture first.
