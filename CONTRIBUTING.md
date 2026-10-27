# Contributing to PSOperator

PSOperator is a security-oriented, fully-local desktop-automation agent. Its core
invariant is simple and load-bearing: **planning proposes, policy decides, only
the executor actuates.** Changes are held to that boundary, and to an AI review
backed by human merge authority.

## Review model

Every PR is reviewed by an AI agent **other than the one that wrote it**, plus
the human who holds merge authority. Verify every finding against the code
before acting; the reviewer can be wrong.

### The independent reviewer — required

Any capable agent that did not write the change qualifies: for example the
Codex CLI reviewing a change Claude wrote, or the reverse. Review the **final
head** of the PR. A review of an earlier commit does not cover later pushes, so
after fixes, the reviewer re-reviews the change since its last verdict.

### CodeRabbit — welcome, not required

CodeRabbit is configured in `.coderabbit.yaml` with
`auto_incremental_review: false`, so it reviews a PR once, on the opening
commit. Its limits are enforced per developer per hour, and it is often
rate-limited. When it does review, treat its findings like any other
reviewer's. When it is rate-limited or skipped, the independent agent review
stands in; do not hold a merge waiting for it. To have it review the final
state, comment `@coderabbitai full review` (not `review`, which can silently
skip a small final push).

### The merge bar

A PR is mergeable when the independent reviewer approves the final head, no
Major or Minor findings remain from any reviewer, and CI passes on that head.
Do not block a merge chasing a reviewer to literally zero comments: fold in the
Trivial nits that are worthwhile and track or drop the rest. The human with
merge authority owns the merge; they may give standing approval to merge once
those conditions hold. Merge pinned to the reviewed head, then confirm CI on
`main`.

## Nothing private, anywhere

This repository is public. No private-LAN address, home-directory path, or real
hostname belongs in it. That covers files, and also commit messages, PR titles
and PR bodies, which are published just the same. Example values use the
RFC-5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`). A real deployment configures through `PSOPERATOR_*`
environment variables or a local `.env`, never through the repository.

`scripts/privacy_scan.py` enforces this.

- **CI** scans every tracked file, every commit message in a PR, the PR title and
  body, and every commit pushed to `main`.
- **Locally**, enable the hooks once per clone, so a leak is stopped before it is
  committed:

  ```
  git config core.hooksPath scripts/hooks
  ```

  The hooks also read a private denylist of real hostnames from
  `~/.config/pxx/public-denylist` (or `$PRIVACY_DENYLIST`). That file must never
  be added to any repository. Findings name the denylist entry by number, never
  the term.

A test that needs a generic private address, such as one a bind check must
refuse, marks its line with `# privacy: example`. A real address is never
marked.

## The bar for a change

1. **Fail closed at every trust boundary.** Unknown, missing, malformed, or stale
   input is a denial, never a pass.
2. **Every gate needs a negative control** — a test that proves it *fires* on the
   bad case, not just passes on the good one.
3. **Protected paths are the trusted control plane** (see the `protected_paths`
   list in `WORKFLOW.md`): the gatekeeper, services, common auth/ipc/schema, and
   the boundary tests. Changes there need independent review by an agent that
   did not write them, under the merge bar above — never self-approved.
4. **Data-egress surfaces come only from operator config/env/CLI**, never a
   checked-in file. No secrets, organisation names, internal hostnames, or
   internal private-LAN addresses in tracked content. Example presets use
   documentation-range placeholders (RFC-5737) throughout: `192.0.2.0/24`
   (TEST-NET-1) for the home fleet, `203.0.113.0/24` (TEST-NET-3) for work.
   There is no approved exception — a real deployment address in a tracked file
   is a defect regardless of which range it comes from.
5. **Evidence beats assertion.** "Verified"/"proven"/"attested" language must be
   backed by an artifact; claims must match what the code and tests do.

Run `pytest -q`, `ruff check`, and `ruff format --check` before pushing, and
`pxx workflow validate` for governed work. See `WORKFLOW.md` for the full
machine-readable contract and `docs/agent-team.md` for the multi-agent model.
