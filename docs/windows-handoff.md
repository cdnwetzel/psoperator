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
| Python 3.13 | PSOperator (3.12 no longer ships Windows installers) | `py -3.13 --version` |
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
Windows. Paths use forward slashes.

1. **`python3` must be real Python.** The privacy hooks call `python3`, which a
   Windows Python install does not provide; the Microsoft Store alias of that
   name is a stub. Turn off the `python3` app execution alias in Windows
   settings, then add a shim:

   ```
   mkdir -p ~/bin
   printf '#!/bin/sh\nexec py -3.13 "$@"\n' > ~/bin/python3
   chmod +x ~/bin/python3
   python3 --version     # must print Python 3.13.x
   ```

   Git Bash puts `~/bin` on `PATH` when it exists; open a new shell if not.
2. **GitHub over SSH.** Generate a key, and have the operator add it to the
   repository owner's account.
3. **Clone, enable the privacy hooks, and add both push remotes.** The
   operator supplies the owner and the private mirror's remote; replace every
   `<...>` placeholder before running. One `git push` must update both:

   ```
   git clone git@github.com:<owner>/psoperator.git
   cd psoperator
   git config core.hooksPath scripts/hooks
   git config user.name "<name>"
   git config user.email "<email>"
   git remote set-url --add --push origin git@github.com:<owner>/psoperator.git
   git remote set-url --add --push origin <private-mirror-remote>
   git remote -v         # one fetch URL, two push URLs
   ```
4. **Private denylist.** Copy it from the operator to
   `~/.config/pxx/public-denylist` by hand. It never goes through git. Without it
   the hooks catch private addresses but not real names.
5. **Prove the hooks fire** (negative controls; neither commit may succeed):

   ```
   git commit --allow-empty -m "probe $(printf '10.%s.%s.%s' 0 1 5)"   # private address
   git commit --allow-empty -m "probe $(grep -v -e '^#' -e '^$' ~/.config/pxx/public-denylist | head -1)"
   ```

   Both must be refused **by the privacy hook**: the output must name the
   rule, `private-lan-address` for the first and `denylist term` for the
   second. A refusal without that line (for example, a missing Git identity)
   proves nothing. If either commit succeeds or fails for another reason, stop;
   the privacy gate is not working on this machine.
6. **Install:**

   ```
   py -3.13 -m venv .venv
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
8. **Agents.** Install Claude Code with its native Windows installer, and the
   Codex CLI with `npm install -g @openai/codex`; check `claude --version` and
   `codex --version`. Then sign in to both, and run `gh auth login`.
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
