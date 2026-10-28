# Windows endpoint handoff

For the operator and for a coding agent (Claude Code) working on the Windows
test endpoint described in `docs/pilot-charter.md`. An agent there starts with
only this repository, so everything it must know is here or linked from here.

## 0. Start here (agent on the first endpoint)

Read `docs/pilot-charter.md`, then this file, then `CONTRIBUTING.md`. State on
the first endpoint as of 2026-10-28:

| step | state |
| --- | --- |
| §1 machine tools: Git, Python 3.13.17, GitHub CLI, Node | done, verified |
| §2.1 `python3` shim pinned to the all-users 3.13.17 | done, verified |
| §2.2 GitHub SSH keys for both accounts | done, both authenticate |
| §2.3 clone, hooks, identity, both push remotes | done; whole tree checked out LF |
| §2.4 private denylist | done |
| §2.5 hook negative controls | done, both refused by the hook |
| §2.6 install, §2.7 baseline | done; 489 passed, 19 failed, 14 skipped (`docs/windows-probe.md`) |
| §2.8 agents | done; Claude Code, Codex and `gh` signed in |
| §4 probe | done; verdict in `docs/pilot-charter.md` |
| D-01 owner-only checks | done; key, IPC secret and gate state verified by DACL (`docs/deployment-isolation.md`) |
| D-01 Windows CI job | done; the whole suite runs on `windows-latest` |
| next | rest of roadmap D-01: the capture frame-hash pin test on Windows |

Pick up at the first row not marked done: check it, report in one short
message, and continue. Stop and ask before anything that is not in this file,
and before any input to the application. Never push `main`; feature branches
only.

## 1. Machine setup (from the management host, over SSH)

The endpoint runs OpenSSH Server, with key-based access for an admin account.
Install machine-wide, and check each version afterwards:

| tool | why | check |
| --- | --- | --- |
| Git for Windows | clone, hooks; its Git Bash is the shell Claude Code uses | `git --version` |
| Python 3.13 | PSOperator; 3.13.17 is the last 3.13 release with a Windows installer, and CI tests 3.11–3.13 | `& "C:\Program Files\Python313\python.exe" --version` |
| Node.js LTS | the Codex CLI | `node --version` |
| GitHub CLI | PRs and CI checks | `gh --version` |

Use the vendors' installers, each checked against the vendor's published
checksum or signature, and its Authenticode signer, before it runs. `winget` is
unreliable inside SSH sessions.

Claude Code and the Codex CLI install **per user**, in the desktop session
(section 2): an install over SSH would land in the admin account's profile.

An SSH session cannot see the logged-in desktop. Nothing that reads or drives
the screen (the probe, the observer, the executor) is run over SSH.

## 2. Desktop session setup (as the user who will run the agent)

Use **Git Bash** for every command below; it is the shell Claude Code runs on
Windows. Paths use forward slashes. An MSYS2 shell (prompt `UCRT64` or
`MSYS`) shares the same home directory but has its own `git` and `PATH`
order, so do not mix it in.

1. **`python3` must be the verified Python.** The privacy hooks call
   `python3`, which a Windows Python install does not provide. The names that
   may already answer to it are traps: the Microsoft Store alias is a stub,
   and the Python Install Manager's `python3` (and `py -3.13`) can pick a
   different, per-user 3.13 than the one installed in §1. Turn off the
   `python3` app execution alias in Windows settings, then pin a shim to the
   all-users interpreter by its path:

   ```
   mkdir -p ~/bin
   printf '#!/bin/sh\nexec "/c/Program Files/Python313/python.exe" "$@"\n' > ~/bin/python3
   chmod +x ~/bin/python3
   hash -r; which python3; python3 --version   # ~/bin/python3, then Python 3.13.17
   ```

   Git Bash puts `~/bin` on `PATH` when it exists; open a new shell if not.
2. **GitHub over SSH, both accounts.** Generate one key for the repository
   owner's account and one for the private mirror's account, map each in
   `~/.ssh/config` (the mirror under its own `Host` alias), and have the
   operator add each public key to its account. `ssh -T` to each host must
   greet the right account.
3. **Clone, enable the privacy hooks, and add both push remotes.** The
   operator supplies the owner and the private mirror's remote; replace every
   `<...>` placeholder before running. One `git push` must update both:

   ```
   git clone git@github.com:<owner>/psoperator.git
   cd psoperator
   git config core.hooksPath scripts/hooks
   git config user.name "<name>"
   git config user.email "<user>@users.noreply.github.com"   # never a work address
   git remote set-url --add --push origin git@github.com:<owner>/psoperator.git
   git remote set-url --add --push origin <private-mirror-remote>
   git remote -v         # one fetch URL, two push URLs
   git ls-files --eol scripts/hooks   # both lines must show w/lf
   ```

   `.gitattributes` keeps every text file LF. A clone made before it existed may
   hold CRLF copies, which break the hooks (they run without the denylist).
   If `git ls-files --eol` shows `w/crlf`, re-check out the hooks and look
   again:

   ```
   rm scripts/hooks/pre-commit scripts/hooks/commit-msg
   git checkout -- scripts/hooks
   git ls-files --eol scripts/hooks
   ```
4. **Private denylist.** Copy it from the operator to
   `~/.config/pxx/public-denylist` by hand. It never goes through git. Without it
   the hooks catch private addresses but not real names.
5. **Prove the hooks fire** (negative controls; no commit may succeed):

   ```
   git commit --allow-empty -m "probe $(printf '10.%s.%s.%s' 0 1 5)"   # private address
   git commit --allow-empty -m "probe $(grep -v -e '^#' -e '^$' ~/.config/pxx/public-denylist | head -1)"
   git -c user.email="probe@$(grep -v -e '^#' -e '^$' ~/.config/pxx/public-denylist | head -1).test"        commit --allow-empty -m "probe"                                 # identity
   ```

   Each must be refused **by the privacy hook**: the output must name the
   rule, `private-lan-address` for the first, `denylist term` for the
   second, and `commit-identity` with `denylist term` for the third. A refusal without that line (for example, a missing Git identity)
   proves nothing. If either commit succeeds or fails for another reason, stop;
   the privacy gate is not working on this machine.
6. **Install:**

   ```
   python3 -m venv .venv          # the pinned interpreter, not py -3.13
   .venv/Scripts/python --version  # Python 3.13.17
   .venv/Scripts/python -m pip install -e ".[dev,a11y,perception]"
   ```
7. **Baseline.** Run `.venv/Scripts/python -m pytest -q` and
   `.venv/Scripts/python -m ruff check psoperator tests scripts`. The suite has
   only run on Linux and macOS until now, so expect some failures. In
   particular, `AttestationGate` refuses persistent gate state on Windows by
   design: it cannot verify file ownership there
   (`psoperator/gatekeeper/attestation_gate.py`, `_read_state_bytes`). Record
   the failing tests as the Windows baseline in the probe PR. Do not weaken a
   refusal to make a test pass; porting those checks is part of roadmap D-01.
   (Since ported: the gate verifies its state by DACL, and the suite passes
   on Windows, in CI as well.)
8. **Agents.** Install Claude Code with its native Windows installer, which
   runs in **PowerShell** (the one exception to Git Bash above), and the Codex
   CLI with `npm install -g @openai/codex`. Open a new Git Bash, check
   `claude --version` and `codex --version`, sign in to both, and run
   `gh auth login`.
9. Open the target application on this desktop, with a synthetic test record
   loaded.

## 3. Working rules

These are the operator's standing rules. They apply to every change.

- **Updates:** short and frequent.
- **Nothing private, anywhere** (`CONTRIBUTING.md`). Do not name the
  application, its records, the endpoint, or the organisation in files, commit
  messages, PR titles or PR bodies. The hooks scan commits; scan PR text
  yourself before posting it:

  ```
  python3 scripts/privacy_scan.py --denylist ~/.config/pxx/public-denylist text --name pr < pr.txt
  ```

  Exit 0 is clean and 1 is a finding. Empty output is not proof: check the
  exit code, and keep the step 5 controls passing.
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
- **Scope.** Work only in this repository, on this endpoint. Do not change the
  monitoring system, other endpoints, or other repositories. Stop and ask the
  operator before anything this file does not cover.

### The PR loop, as commands

Run from the clone in Git Bash. `H` is the head you just pushed.

```
H=$(git rev-parse HEAD)
# CI on that exact commit (wait until every check has completed, then read them)
until [ "$(gh api repos/<owner>/psoperator/commits/$H/check-runs -q '[.check_runs[]|select(.name!="CodeRabbit" and .status!="completed")]|length')" = 0 ]; do sleep 15; done
gh api repos/<owner>/psoperator/commits/$H/check-runs -q '.check_runs[]|"\(.name) \(.conclusion)"'

# independent review of the final head; stdin must be closed or it waits forever
codex exec -s read-only "Review 'git diff main...$H' ... Reply Blocking / Non-blocking / Nit, then APPROVE or CHANGES NEEDED." < /dev/null

# merge only after APPROVE and all checks success on $H, pinned to $H
gh pr merge <n> --squash --delete-branch --match-head-commit "$H"
git checkout main && git pull   # then read CI on the new main head the same way
```

An empty or missing reviewer reply is not an approval; run it again.

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

**Done 2026-10-28** (`docs/windows-probe.md`). Lessons for the next session on
the endpoint:

- Read the application through `Desktop(backend="win32")` or
  `EnumChildWindows`: milliseconds, against minutes for UI Automation here.
- Before any capture or key, check that the application is the foreground
  window **and** on top at the target point (`WindowFromPoint`). The agent's
  own terminal can come to the front between steps.
- Before every key, check that focus is on the intended control. Some screens
  move focus when they open.
- Find the application by process and window class, and check the process
  start time: titles change and Windows reuses process ids.
- Each input step needs the operator's approval for that step. The keystroke
  sequences come from the operator's navigation manual, which stays private.
