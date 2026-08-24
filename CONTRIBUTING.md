# Contributing to PSOperator

PSOperator is a security-oriented, fully-local desktop-automation agent. Its core
invariant is simple and load-bearing: **planning proposes, policy decides, only
the executor actuates.** Changes are held to that boundary, and to a two-tier AI
review model backed by human merge authority.

## Review model

Two independent AI reviewers, one blocking and one advisory, plus the human who
merges. Their value is *disagreement* — a finding one raises and the other misses
is worth more than either's aggregate score. Verify every finding from either
reviewer against the code before acting; both can be wrong.

### CodeRabbit — primary, blocking

**CodeRabbit must pass before any PR is merged.** It is configured in
`.coderabbit.yaml` with `auto_incremental_review: false` — it reviews a PR **once,
on the opening commit, not on every push.**

That is deliberate: CodeRabbit's limits are enforced **per developer per hour**,
spent per push, so a 3–4 push fix loop otherwise burns a whole hour's budget on
one PR (we hit exactly that wall). The trade-off is real — after the opening
review the status check stays green while you push fixes, a gate passing on code
it did not read.

> **Before merging, comment `@coderabbitai full review` on the PR and wait for
> the review of the final state.** Use `full review`, not `review`: a small final
> push is otherwise silently skipped as "similar to previous changes," leaving no
> verdict at all. If nothing has been pushed since CodeRabbit's most recent
> review, that review already covers the final state and no re-trigger is needed.

**Note on substantial new modules:** a module assembled over several commits needs
at least one `@coderabbitai full review` of the whole thing before merge.
Incremental review only diffs each push, so it structurally never re-reads the
assembled whole — real defects can hide in code that already passed increment-by-
increment (this repo has seen exactly that).

### Greptile — advisory, second opinion

Greptile runs as a **second, independent reviewer**, configured in `greptile.json`
with `statusCheck: false` — it does **not** gate merges, and `triggerOnUpdates:
false` — it does **not** re-review every push. It is the double-check, especially
when CodeRabbit is rate-limited. Trigger a run on demand with `greptile review`
(reviews the current branch against its base). Weigh its findings; do not treat
them as blocking. Ordering tip: on a final convergence pass, run the on-demand
`greptile review` **first**, fold in what it finds, then spend the one CodeRabbit
review on the settled state — so the rate-limited reviewer sees final code.

### The merge bar

A PR is mergeable when **no Major or Minor findings remain** from either reviewer
(and internal review + tests are clean). Do **not** block a merge chasing an
assertive reviewer to literally zero comments — on a substantial module it will
almost always surface a couple of Trivial style/coverage/refactor nits on any
diff, and chasing them burns rate-limited reviews for non-defects (the exact
"over-flagging trains people to ignore reviewers" failure mode). Fold in the
Trivial nits that are genuinely worthwhile; track or drop the rest. Major/Minor
findings **do** block. Human authority owns the merge either way.

## The bar for a change

1. **Fail closed at every trust boundary.** Unknown, missing, malformed, or stale
   input is a denial, never a pass.
2. **Every gate needs a negative control** — a test that proves it *fires* on the
   bad case, not just passes on the good one.
3. **Protected paths are the trusted control plane** (see the `protected_paths`
   list in `WORKFLOW.md`): the gatekeeper, services, common auth/ipc/schema, and
   the boundary tests. Changes there need independent human review — never
   self-approved or self-merged.
4. **Data-egress surfaces come only from operator config/env/CLI**, never a
   checked-in file. No secrets, organisation names, internal hostnames, or
   internal private-LAN addresses in tracked content; example presets use
   documentation-range placeholders (RFC-5737). The `10.0.1.0/24` range and
   device-model hostnames are the one approved exception (operator policy).
5. **Evidence beats assertion.** "Verified"/"proven"/"attested" language must be
   backed by an artifact; claims must match what the code and tests do.

Run `pytest -q`, `ruff check`, and `ruff format --check` before pushing, and
`pxx workflow validate` for governed work. See `WORKFLOW.md` for the full
machine-readable contract and `docs/agent-team.md` for the multi-agent model.
