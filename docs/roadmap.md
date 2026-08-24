# PSOperator product and engineering roadmap

**Document status:** Active

**Applies to:** PSOperator `0.1.x` and later

**Last reviewed:** 2026-08-19

**Current phase:** `v0.2` execution — trust-boundary closure

## 1. Purpose

This roadmap defines the sequence by which PSOperator moves from a tested
architecture starter to a defensible production pilot. It identifies release
outcomes, dependencies, acceptance criteria, and explicit non-goals. It is the
authoritative prioritization document; [`integration.md`](integration.md)
records how the original prototypes were combined, while this document governs
what happens next.

The roadmap is capability-based rather than date-based. A milestone is complete
only when its exit criteria are demonstrated. Passing time, completing most
tasks, or producing a demo does not satisfy a release gate.

## 2. Current baseline: `v0.1`

The current repository provides one installable `psoperator` package with:

- cross-platform `mss` capture and optional UVC capture;
- tile-diff and perceptual-hash keyframe selection;
- accessibility/OCR-derived, frame-bound UI element references;
- local-model and deterministic planners;
- strict structured actions with freshness and coordinate validation;
- deterministic T0–T3 risk classification, T2 approval, and a default T3 hard
  block;
- dry-run, `pynput`, and CH9329 executor backends;
- an optional process-separated gatekeeper/executor topology with authenticated,
  expiring, nonce-protected executor messages;
- a persistent kill switch and a hash-chained JSONL audit log;
- trajectory recording and layered skill replay foundations;
- 205 automated tests, Ruff enforcement, buildable wheel/sdist artifacts, and
  wheel-install smoke verification.

This baseline is suitable for development, threat-model validation, and dry-run
experimentation. It is not approved for unattended production automation.

## 3. Priority model

Work is ordered using the following priorities:

| Priority | Meaning |
| --- | --- |
| P0 | Required to preserve or establish a claimed security boundary |
| P1 | Required for a reliable, supervised pilot |
| P2 | Improves usability, coverage, performance, or maintainability |
| P3 | Exploratory capability with no release dependency |

Within a milestone, P0 work blocks P1 work when the P1 behavior relies on the
unfinished boundary. Every trust-boundary change must fail closed when a
dependency is missing, unavailable, invalid, or stale.

## 4. Critical path

```text
Attested perception
        ↓
Window/focus binding
        ↓
Post-action verification
        ↓
One validated platform workflow
        ↓
Digest-bound approval + compiled skills
        ↓
Operational hardening
        ↓
Production pilot
```

Model-quality work, additional platforms, and hardware experiments may proceed
in parallel, but none replaces a critical-path release gate.

## 5. Milestone `v0.2`: trust-boundary closure

**Objective:** Ensure a compromised planner cannot manufacture the perception
evidence used by the gatekeeper to validate or classify an action.

**Priority:** P0

**Depends on:** `v0.1` IPC, schema, freshness, gatekeeper, and audit foundations

**Execution note:** Governed roadmap work currently targets PXX 2.5.3. Its
trusted `plan` and `reviewer` model lanes may improve task decomposition and
independent review evidence, but they are development-control-plane inputs, not
PSOperator runtime security dependencies or release authority. Role endpoint
routing must come from trusted operator configuration rather than this
repository.

### Deliverables

#### R-201 — Independent observer service

**Implementation status:** Integrated into `main` on 2026-08-17 after independent
review, with recorded finding disposition and final verification evidence.

- Run capture and perception outside the planner process.
- Assign each observation a monotonic frame sequence, capture timestamp, screen
  dimensions, content hash, and bounded element inventory.
- Expose snapshots through bounded JSON IPC without pickle or executable
  serialization.
- Define lifecycle and health behavior for observer unavailability.

#### R-202 — Attested snapshot envelope

**Implementation status:** Implemented, independently reviewed, and integrated
into `main`. Gatekeeper-side verification of the envelope is tracked separately
as R-203 below.

- Sign the canonical snapshot payload with credentials unavailable to the
  planner account.
- Include signature version, key identifier, signed observer epoch, issued-at
  time, expiry, and nonce.
- Define key provisioning and rotation without silently accepting an old or
  unknown key.
- Bind every element ID to the signed frame and reject duplicate IDs.

#### R-203 — Gatekeeper verification and replay defense

- Verify snapshot signature, key ID, expiry, monotonic sequence, and nonce before
  evaluating the action.
- Reject any mutation to frame metadata, element label, role, source, confidence,
  or bounding box.
- Reject actions targeting an element absent from the verified snapshot.
- Keep coordinate-only fallback explicit and subject it to signed frame bounds.
- Audit verification failures without executing or requesting approval.

#### R-204 — Adversarial multiprocess tests

- Launch observer, planner client, gatekeeper, and dry-run executor as real
  processes in integration tests.
- Cover modified payloads, forged signatures, expired snapshots, replayed
  nonces, rolled-back frame sequences, unknown keys, invented targets, executor
  bypass attempts, and unavailable services.
- Confirm the planner package and process environment have no snapshot-signing
  or executor-authentication credential.

#### R-205 — Deployment boundary documentation

- Define service accounts, file ownership, secret permissions, IPC exposure,
  startup order, shutdown order, and recovery behavior.
- Document which guarantees remain unavailable when all services share one OS
  account.

### Exit criteria

`v0.2` is complete when:

1. The gatekeeper accepts only independently attested snapshots.
2. Changing any signed snapshot field causes deterministic rejection.
3. Expired, replayed, and out-of-order snapshots cannot reach approval or
   execution.
4. A planner-process test fixture with arbitrary request control cannot mint a
   valid snapshot or call the executor successfully.
5. All rejections are present in a valid audit chain.
6. Unit, multiprocess integration, lint, format, build, and wheel-install checks
   pass in automation.

## 6. Milestone `v0.3`: reliable supervised vertical slice

**Objective:** Complete one real, repeatable desktop workflow on one declared
pilot platform with correct focus, execution, and post-action evidence.

**Priority:** P0/P1

**Depends on:** `v0.2`

The pilot OS and target application must be recorded in a decision note before
implementation. macOS is a practical candidate for the current development
host; Windows may be selected instead if the first target workflow depends on
UI Automation or an existing Windows application.

### Deliverables

#### R-301 — Window and application identity

- Add process/application identity, window identity, title, bounds, and focus
  state to attested perception evidence where the platform supports them.
- Bind each executable action to its intended window.
- Re-check window identity and focus immediately before input.
- Reject focus changes, closed windows, secure desktops, and unsupported
  privilege transitions.

#### R-302 — Post-action verification

- Capture fresh evidence after each executed action.
- Represent explicit postconditions rather than treating the next loop
  iteration as implicit success.
- Record requested action, precondition result, execution result, postcondition
  result, and before/after frame hashes.
- Define bounded retry behavior that cannot repeat a sensitive action without a
  new approval.

#### R-303 — Production-quality provider for the pilot OS

- Finish the selected accessibility provider: macOS AX, Windows UIA validation,
  or Linux AT-SPI.
- Select and benchmark the corresponding capture path.
- Validate OCR fallback and coordinate translation across scaling, multiple
  displays, and negative monitor origins where applicable.

#### R-304 — Reference workflow

- Select a narrow workflow with deterministic success criteria.
- Provide a fixture or test application where practical.
- Run first in dry-run/shadow mode, then supervised real-input mode.
- Record reliability, latency, failure categories, approval counts, and audit
  verification results.

#### R-305 — Hardware-path validation

- Exercise UVC capture and CH9329 execution against real hardware if crash-cart
  operation is in pilot scope.
- Confirm configured resolution, coordinate scaling, baud rate, key mapping,
  disconnect behavior, and kill-switch handling.
- Keep hardware validation out of the release gate when Topology B is not part
  of the selected pilot.

### Exit criteria

`v0.3` is complete when:

1. One declared platform and application complete the reference workflow under
   supervision with reproducible setup instructions.
2. Wrong-window, changed-focus, stale-frame, and failed-postcondition tests all
   fail closed.
3. Every real input has matching pre-action, decision, execution, and
   post-action audit evidence.
4. The same workflow succeeds in at least 95 of 100 recorded-skill runs in the
   controlled test environment, with zero unapproved sensitive actions.
5. Platform-specific limitations are recorded in the support matrix.

## 7. Milestone `v0.4`: human approval and skills

**Objective:** Make supervised sensitive actions and deterministic repeatable
workflows usable without weakening the gatekeeper.

**Priority:** P1

**Depends on:** `v0.2`; post-action portions depend on `v0.3`

### Deliverables

#### R-401 — Digest-bound approval protocol

- Bind each approval request to the action digest, snapshot hash, policy hash,
  target/window identity, risk tier, expiry, and one-time nonce.
- Implement the ntfy callback receiver or another operator-controlled channel.
- Reject late, duplicate, mismatched, unsigned, and already-consumed responses.
- Require a new approval when action content or current evidence changes.

#### R-402 — Skill compiler

- Convert raw trajectories into parameterized `Skill` definitions.
- Collapse redundant pointer motion and repeated events.
- Prefer hotkeys and accessibility locators over OCR, image, or recorded
  coordinates.
- Learn bounded waits and derive candidate preconditions/postconditions.
- Require operator review before a compiled skill becomes executable.

#### R-403 — Skill storage and versioning

- Define a versioned on-disk format and migration policy.
- Store author, source trajectory digest, policy compatibility, parameters, and
  review status.
- Detect edits and refuse unreviewed or schema-incompatible skills.

#### R-404 — Grounding completion

- Implement template-image grounding with confidence thresholds and ambiguity
  rejection.
- Preserve the cheapest-first locator ladder.
- Record which locator layer resolved each step and prevent a lower-confidence
  fallback from silently bypassing policy.

### Exit criteria

`v0.4` is complete when:

1. A T2 approval cannot authorize any action or snapshot other than the one the
   operator reviewed.
2. Approval timeout, duplicate response, and callback outage all fail closed.
3. A recorded reference workflow can be compiled, reviewed, versioned, replayed,
   and verified without model planning in the normal path.
4. Skill fallback decisions and approval events are fully auditable.

## 8. Milestone `v0.5`: operational hardening

**Objective:** Make the system observable, deployable, and maintainable as a
restricted pilot service.

**Priority:** P1/P2

**Depends on:** `v0.2`; final release gate depends on `v0.3` and `v0.4`

### Deliverables

#### R-501 — Audit sink abstraction and external anchoring

- Separate audit record construction from storage.
- Add a transactional local sink such as SQLite and an optional external sink.
- Periodically anchor the audit tail hash outside the executor host.
- Define recovery and verification behavior after partial writes or storage
  unavailability.

#### R-502 — Service operations

- Add structured logs, health/readiness endpoints, graceful shutdown, bounded
  queues, and backpressure.
- Document supervisor configuration and restart policy.
- Ensure restarts preserve kill-switch, freshness, nonce, and audit safety.

#### R-503 — Continuous integration

- Run tests, Ruff, build, and wheel-install smoke checks on every change.
- Establish a supported Python matrix and OS matrix.
- Keep hardware tests separately marked and runnable on a controlled bench.
- Add coverage reporting for security-critical modules.

#### R-504 — Policy tooling

- Validate policy files against a versioned schema.
- Compute and display policy diffs and hashes before activation.
- Add regression fixtures for application-specific sensitive and destructive
  targets.
- Prevent operator extensions from de-escalating built-in policy.

#### R-505 — Release engineering

- Define versioning, changelog, artifact provenance, dependency review, and
  rollback procedure.
- Produce a reproducible installation and restricted-service deployment guide.

### Exit criteria

`v0.5` is complete when:

1. CI enforces the declared support matrix and package smoke tests.
2. Audit history can be verified against an independently stored anchor.
3. Service restart, dependency outage, full queue, and partial audit-write tests
   have documented fail-closed outcomes.
4. Policy changes are schema-validated, hashed, reviewed, and regression-tested.

## 9. Milestone `v1.0`: production pilot readiness

**Objective:** Authorize a bounded, supervised production pilot for explicitly
listed workflows, applications, platforms, and executor backends.

**Priority:** Release gate

**Depends on:** `v0.2` through `v0.5`

### Exit criteria

`v1.0` requires all of the following:

- a published threat model and support matrix;
- no unresolved P0 or P1 defects in the approved pilot scope;
- restricted service accounts and reviewed secret ownership;
- independently attested perception and authenticated execution;
- digest-bound, expiring, one-time approval for every T2 action;
- default hard blocking for T3 actions;
- externally anchored, verified audit records;
- demonstrated kill-switch behavior during active workflows and service
  restarts;
- repeatable deployment, rollback, backup, and incident-response procedures;
- measured reliability for every approved skill and a documented rollback when
  its environment changes;
- explicit operator acceptance of residual risks.

`v1.0` does not authorize arbitrary unattended desktop operation. Production
approval applies only to the workflows and environments named in the release
record.

## 10. Deferred and non-goals through `v1.0`

- Claiming human-level success on open-ended GUI tasks.
- Defeating EDR, anti-cheat, or synthetic-input detection.
- Topology A control of firmware, lock screens, secure desktops, or pre-login
  environments.
- Treating Windows, macOS, and Linux as equally supported before each has a
  validated provider and reference workflow.
- Allowing a model to assign or lower its own action risk.
- Automatically executing newly recorded or model-generated skills without
  operator review.
- Cloud-model fallback that silently sends screenshots or desktop metadata off
  the local system.

These items require separate design decisions and must not enter through an
implementation shortcut or undocumented configuration flag.

## 11. Cross-cutting definition of done

Every roadmap item that changes runtime behavior must include:

1. A documented threat and failure analysis.
2. Unit tests for expected and malformed inputs.
3. An integration test across every affected process boundary.
4. An audit assertion for success and failure paths.
5. Fail-closed behavior for missing dependencies and unavailable services.
6. Ruff lint and format compliance.
7. Passing package build and wheel-install smoke verification.
8. README, configuration, and support-matrix updates where behavior changes.
9. No new executor or input-library import path from planning code.

Hardware- or OS-specific work must additionally record the environment and
manual validation procedure when it cannot run in ordinary CI.

## 12. Roadmap governance

- Changes to milestone order or exit criteria require a documented rationale in
  this file or an adjacent decision record.
- Security boundary regressions are P0 regardless of feature impact.
- New capability belongs in the earliest milestone whose exit criteria depend
  on it; otherwise it remains a parallel P2/P3 experiment.
- Completed items should link to their implementation, tests, and release note.
- The roadmap should be reviewed whenever a milestone closes or the threat model
  changes materially.
