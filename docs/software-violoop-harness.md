# The SoftLoop harness — sovereign coding loops, no cloud model driving

`psoperator.harness` is the deterministic runtime that lets a **local** model
do the kind of build-and-verify work a person (or a cloud assistant) would
otherwise babysit. It is the codification of a real session: a temperature-
converter GUI was built by a LAN coder model under `pxx`, validated by tests
and an on-screen acceptance check, and every failure was handled by a fixed
rule instead of a human judgment call. Those rules are this module.

The point is time. A harness that reliably runs the routine loop unattended —
and stops cleanly, with evidence, exactly when it needs a person — is hours a
week returned to the operator. That is the design criterion: **measured by how
rarely it needs you**, not by how clever it is.

## Shape

A state machine over the `WORKFLOW.md` states
(`idle → planning → executing → verifying → reviewing → completed|failed`),
driving three narrow seams and one decision function:

| Seam | Role | Real adapter |
|---|---|---|
| `Coder` | writes code, bounded + netted | `PxxCoder` → `pxx loop --scope … PXX_TEST_COMMAND=…` |
| `Gate` | runs the acceptance command, reports **every** violation | `CommandGate` (pytest + `ui_acceptance.py`) |
| `VisionJudge` | optional on-screen check (clipped/tiny/duplicate) | a UI-TARS-class VLM; `NullVisionJudge` abstains |
| `Reviewer` | cheap local review tier, *inside* the loop | `PxxReviewer` → `pxx review` (APPROVE/REVISE); `NullReviewer` abstains |

No planner output changes control flow — the state machine and the
`EscalationLadder` own that. A model can only propose an edit; the harness
decides what happens next.

### Tiered review (offline-first)

Review is a ladder of its own, cheapest-and-most-local first, so the paid
tiers only see what survives the free ones:

1. **Local (tier 1) — `Reviewer` / `pxx review`.** Runs *inside* the loop on
   every gate-passing change, unlimited and offline. A REVISE gets a bounded
   number of fix passes (`Budget.max_review_revisions`, default 1); whatever it
   still flags is recorded in `Evidence.review_findings` and handed up — it
   never nitpick-loops a gate-verified change. This tier is the rate-limiter
   that protects the next one's quota.
2. **PR gate (tier 2) — CodeRabbit.** Fires once per PR (quota'd), so tier 1
   must pre-filter; the harness must not open PRs faster than tier 1 clears.
3. **Pre-merge (tier 3) — a stronger model (Claude) + one-shot Codex/Kimi.**
   Reads the evidence bundle + diff and says "safe to merge" before anything is
   set fully autonomous on production code. Tie-breaker for hard calls.
4. **Merge — the human.** Never blind; the whole ladder exists to make that
   final call cheap and well-evidenced, not to remove it.

## The escalation ladder

When a gate fails, the response is deterministic and escalates only when the
cheaper move didn't help:

1. **retry** — one re-run on the same lane (small models fumble the edit tool,
   then land on the second try).
2. **split** — turn a multi-violation gate into one focused fix per violation,
   then re-verify the parent once. *Requires a collect-all gate.* This is the
   whack-a-mole fix: a gate that reveals one failure per round multiplies
   rounds.
3. **escalate** — move up a model lane (`small → standard → deep`). Proven
   boundary: a 14B lands two-line edits but fumbles whole functions; a 20–30B
   handles them.
4. **judge** — ask the vision model whether the screen matches intent (for GUI
   work where the text gate can't see layout).
5. **review** — bundle evidence and stop for a human. The top rung, never
   skipped. Thrashing is a bug, not a fallback.

Stall detection short-circuits the ladder: two rounds that changed nothing and
produced the identical violation set jump straight past `retry`.

## Why these exact rules (session evidence)

Each rung encodes a specific thing that happened, now in
the harness tests (and the project's agent-gate-design-rules notes):

- **collect-all gates** — a sequential assert surfaced one widget-too-small at
  a time and cost three model rounds; a gate that returns *all* violations lets
  `split` fix them in one pass.
- **exact-match verification** — a substring check once accepted `180212.0` as
  success; gates compare full values.
- **watchers cover every terminal state** — a waiter that greps only for the
  success marker hangs forever on `BUDGET_EXCEEDED`; the harness treats budget
  exhaustion as an explicit `→ reviewing/failed` with a budget note.
- **fail-closed seams** — a task with no gate command is refused; a gate that
  exits non-zero with no parsed failures still fails with the raw tail.

## Boundaries (honest)

- The harness is pure and unit-tested with fakes; `adapters.py` is the only
  part that shells out. Endpoints/models are **operator-supplied** via
  `LanePolicy` — never tracked, per the `WORKFLOW.md` data-egress rule.
- `VisionJudge` and the local `Reviewer` are the two *advisory* seams that fail
  open (a missing vision model or local reviewer must not block a text-verified
  change — `NullVisionJudge`/`NullReviewer` both abstain); the `Coder` and
  `Gate` seams fail closed.
- This drives coding loops. It does not relax the product's trust boundary:
  the gatekeeper, audit chain, kill switch, and human release authority are
  unchanged and remain binding.

## On a never-seen codebase

The same machine, two added disciplines — **planned, not yet wired** (see
Status): (1) a read-only mapping pass (`pxx ask` + an embeddings index) before
any edit, and (2) a *characterization* first step — the harness's first task on
untested code would pin current behavior as gates a human approves, so later
`COMPLETED` means "still correct," not "changed something." Tighter `--scope`
and mandatory review would complete the fence.

## Status

Design + core + adapters + the local-review (tier-1) seam landed with tests.
**Proven live end-to-end** against the tempconv-gui repo on orin1: the harness
drove gpt-oss:20b (LAN) through the whole pipeline with no Claude in the loop —
coding fix → gate verification → local review → committed fix — and produced
the evidence bundle. Not yet wired: a CLI entry (`psoperator harness run`), the
`ntfy` completion notification (the walk-away signal — the evidence bundle to
your phone), and the never-seen-codebase pre-step (read-only mapping + behavior
characterization). Those are next.
