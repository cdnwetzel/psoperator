# Multi-agent engineering model

**Status:** Active

**Applies to:** All human and automated contributors

**Last reviewed:** 2026-08-19

## Purpose

PSOperator uses several coding agents because implementation, adversarial
review, platform validation, and release judgment are different jobs. This
document assigns those jobs, defines their authority, and prevents a collection
of capable tools from becoming an unreviewed multi-writer system.

The operating rule is:

> One task has one accountable author, one isolated branch or worktree, and an
> independent reviewer. No agent approves or merges its own security-sensitive
> contribution.

The product roadmap remains authoritative for priorities and release exit
criteria. This document governs how the team executes that roadmap.

## Team and responsibilities

| Participant | Role | Primary responsibility | Default authority |
| --- | --- | --- | --- |
| Codex integration lead | Release captain and coordination gateway | Decomposition, interfaces, integration, evidence collection, and `main` | May integrate reviewed work; does not provide the only review of its own changes |
| PSAIOS agent | Architecture and governance peer | Challenge trust-boundary claims, review decisions and release evidence | Coordination artifacts and review; no implicit product-write authority |
| Additional Codex agent | Core implementation engineer | Observer, IPC, schemas, and bounded service behavior | Writes only in its assigned product scope and branch |
| Claude Code | Adversarial security reviewer | Threat analysis, negative tests, credential isolation, replay and bypass attempts | Read-only review by default; test-only writes when assigned |
| Kimi Code | Perception and platform engineer | Capture, accessibility, grounding, snapshot construction, platform providers, and skills | Writes only in its assigned product scope and branch |
| Antigravity | Black-box integration and release-readiness engineer | Installation, deployment, multiprocess exercises, workflow validation, and documentation drift | Read-only or test/documentation scope until calibrated |
| PXX 2.5.3 | Governed execution and evidence control plane | Scope, budgets, role-lane resolution, isolated goal nodes, tests, manifests, verification, reviewer-calibration reports, and audit | Enforces configured runs; never grants product or release approval |
| Human owner | Final authority | Secrets, policy exceptions, branch protection, trust-boundary acceptance, and releases | Unrestricted explicit authority |

Role names describe responsibilities, not model quality. Authority is earned by
the task contract and evidence, not inferred from the agent or vendor name.

## Coordination and branch topology

The orphan branch `coord/psoperator-psaios` is an auditable, turn-based message
bus between exactly two active roles: `psoperator-agent` and `psaios-agent`. It
contains coordination records rather than product code. Only the participant
named by `dialog.yaml` as `turn_owner` may write the next numbered turn.

Other agents do not become simultaneous writers on that branch. Codex acts as
the PSOperator-side gateway and carries reviewed information between the
specialist lanes and the serialized PSAIOS dialog.

```text
PSAIOS agent
     <-> coord/psoperator-psaios <-> Codex integration lead
                                         |
                 +-----------------------+-----------------------+
                 |                       |                       |
          Codex worker              Claude Code             Kimi Code
                 |                       |                       |
                 +----------- isolated product branches --------+
                                         |
                                  Antigravity checks
                                         |
                                   tests + PXX
                                         |
                                  reviewed integration
                                         |
                                        main
```

Use one product branch and worktree per task. Recommended names are descriptive,
not permanent identities:

- `agent/codex-r203-verification`
- `agent/claude-r204-adversarial`
- `agent/kimi-r202-snapshots`
- `agent/antigravity-r205-deployment`

If two agents require a durable direct dialog, create a separate two-party
orphan coordination branch. Do not convert an existing serialized dialog into
a multi-writer channel.

## Task admission

Before an agent writes code, the integration lead records:

1. roadmap item or issue;
2. objective and explicit non-goals;
3. base commit;
4. allowed paths and prohibited paths;
5. dependencies and interface assumptions;
6. required tests and acceptance evidence;
7. reviewer and escalation owner.

Do not assign overlapping write scopes concurrently. When overlap is
unavoidable, serialize the work behind a reviewed interface commit.

Trust-boundary files require explicit assignment and independent security
review. They include, at minimum:

- `psoperator/common/auth.py`, `psoperator/common/attestation.py`, and
  `psoperator/common/ipc.py`;
- `psoperator/common/schema.py`;
- `psoperator/gatekeeper/` and `psoperator/services/`;
- `WORKFLOW.md`, `pxx.toml`, `.github/`, and packaging metadata;
- security-boundary tests and roadmap exit criteria.

## Handoff contract

Every implementation handoff must identify:

- author, task, branch, base commit, and candidate commit;
- paths changed and confirmation that the assigned scope was respected;
- behavior delivered and behavior deliberately not delivered;
- tests, lint, formatting, build, and smoke commands with results;
- security assumptions, risks, and unresolved questions;
- PXX run or verification identifiers when PXX performed the work;
- the requested next owner: revise, review, integrate, or decide.

A prose claim such as "tests pass" is not sufficient when command output or a
machine-readable verification packet can be supplied. Git commits remain the
source of truth for code content; PXX audit is metadata-only and does not replace
the diff.

## Review and integration gates

The integration lead applies these gates in order:

1. Confirm the candidate descends from the declared base and contains no
   unrelated changes.
2. Inspect scope, diff, generated files, dependencies, and secret exposure.
3. Run the roadmap-specific tests and the full repository verification suite.
4. Require Claude or PSAIOS review for trust-boundary changes.
5. Run PXX verification or review where configured.
6. Integrate only after the branch is current and the combined tree passes.

PXX model review is also evidence rather than authority. A deterministic PXX
gate may enforce scope or a budget; a model verdict remains limited by reviewer
quality and must not replace required human or independent security review.

## PXX operating rules

PXX 2.5.3 is the default governed runtime for compatible bounded tasks. Use it
from an agent-specific worktree, never from a shared dirty worktree. A `pxx
goal` run may create isolated node worktrees, but it merges completed node
changes back into the root from which the goal was invoked.

The goal planner may use the trusted `roles.plan` model lane, while model review
uses `roles.reviewer` (with `roles.review` retained as an alias). Executable goal
nodes still use one configured backend factory; PXX does not natively route
separate nodes to Codex CLI, Claude Code, Kimi Code, and Antigravity. Those tools
participate through their Git branches and handoff artifacts; PXX orchestrates
its own compatible backend nodes and verifies integration.

The closed role-lane map also declares `author`, `fast`, `verify`, and `embed`,
but a configured lane must not be described as active until a runtime consumer
uses it. Unset lanes inherit the coder model. Select independent model families
deliberately and calibrate judgment lanes before treating their output as review
evidence. Role endpoints are a data-egress surface and must be configured only
through trusted user configuration, environment variables, or CLI flags; a
repository-local `pxx.toml` cannot choose them.

The repository `WORKFLOW.md` is the agent-legible machine contract. The
`[protected_paths]` section declares PSOperator's review-sensitive surface and
is included in the workflow record. The built-in optimizer protected-path
implementation remains PXX-owned; the PSOperator-specific list
must therefore be backed by task scope, branch review, and integration policy.
Do not claim that declaration alone mechanically protects every listed path.

PXX memory may preserve concise project decisions and operational conventions.
Memory is context, not policy: when it conflicts with Git-tracked documentation,
the repository wins. Never store secrets, prompts containing desktop data, raw
screenshots, approval tokens, or private audit content in memory.

## Initial roadmap allocation

For the `v0.2` trust-boundary closure milestone:

1. Claude Code defines the R-202/R-203 security invariants and R-204 adversarial
   test contract.
2. The additional Codex agent's R-201 observer implementation is integrated into
   `main` after independent review.
3. Kimi Code implements canonical snapshot construction and producer-side
   attestation wiring after the interface is fixed.
4. The Codex integration lead integrates R-203 gatekeeper verification and
   replay defense.
5. Antigravity validates the multiprocess deployment and drafts R-205
   operational documentation.
6. PSAIOS reviews the boundary argument and evidence packet.
7. Full tests, PXX verification, and human disposition gate the integrated
   candidate.

This allocation may change through the roadmap governance process, but the
separation between author, reviewer, deterministic gate, and release authority
must remain.

## Adding or removing an agent

A new agent starts read-only. Its onboarding prompt must direct it to the
README, roadmap, this document, `WORKFLOW.md`, the relevant source and tests,
and any coordination branch rules. It receives write authority only after a
bounded task names its scope, evidence, and reviewer.

Remove or quarantine an agent when it repeatedly exceeds scope, fabricates
evidence, weakens a fail-closed boundary, exposes restricted data, or cannot
produce reproducible work. Preserve its commits and handoffs for audit; do not
silently rewrite the record.
