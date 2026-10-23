# Integration record

This document records how the two source prototypes were reconciled into the
root `psoperator` package. It exists so later changes can distinguish
intentional choices from accidental omissions. (The original prototype trees
were removed from this repository during the public-release scrub; this record
of the reconciliation decisions is retained.)

## Chosen foundation

The `softloop` prototype became the mechanical foundation because it already
contained the larger coherent runtime and test surface: frame capture and
diffing, coordinate action parsing, freshness tracking, deterministic risk,
approval backends, JSONL audit chaining, skill record/replay, UVC capture, and
CH9329 execution.

That code was renamed to `psoperator` (the original prototype tree has since
been removed from this repository).

## Capabilities integrated from the security-focused prototype

The following ideas were incorporated as runtime behavior, not only copied as
documentation:

1. **Observed-element identity.** Accessibility and OCR results become
   `UIElementRef` objects bound to one frame. Actions may target an element ID,
   and the gatekeeper resolves its coordinates only after verifying membership
   in the current snapshot.
2. **Planner isolation.** `psoperator.planning` imports shared schemas and
   actions but no executor or input-injection library.
3. **Separate processes.** Loopback JSON services provide an optional
   planner→gatekeeper→executor topology. JSON is length-bounded and never
   deserialized with pickle.
4. **Executor defense in depth.** Gatekeeper-to-executor calls carry an HMAC,
   timestamp, and nonce. The executor rejects malformed, unauthenticated,
   stale, and replayed requests.
5. **Destructive hard block.** T3 is blocked by default rather than becoming
   executable merely because an approval backend returned true.
6. **Persistent kill switch.** The gatekeeper checks an operator sentinel
   before every action and never clears it automatically.

## Resolved design conflicts

### Element IDs versus raw coordinates

Both remain in the action schema because canvas and crash-cart targets may not
expose structured elements. Element IDs are preferred. If one is supplied,
the gatekeeper rejects unknown IDs and overwrites click coordinates with the
observed bounding-box center. Coordinate-only actions still receive freshness,
risk, approval, execution, and audit checks.

### In-process convenience versus process isolation

Both modes remain, but their guarantees are documented separately. In-process
mode is useful for tests and local iteration. Service mode is the intended
trust-boundary topology and authenticates the executor hop. Strong isolation
still depends on separate OS accounts and filesystem permissions.

### T3 approval versus hard blocking

The security-focused prototype's hard-block policy became the safe default.
Operators can explicitly disable `hard_block_t3`, in which case the inherited
T3 approval requirement still applies. There is no accidental configuration
path from the default to automatic T3 execution.

### JSONL versus SQLite audit

The `softloop` JSONL chain remains the default because it is dependency-free,
portable, and already covered by tests. The abstraction is intentionally small
enough to add a SQLite or external sink later. Production deployments should
anchor tail hashes outside the executor host to make tail truncation evident.

## Remaining integration work

The prioritized milestones, dependencies, acceptance criteria, and release
gates for this work are maintained in [`roadmap.md`](roadmap.md).

- Make the process-separated gatekeeper consume independently captured frame
  evidence rather than trusting a planner-submitted snapshot as its only view.
- Complete macOS AX and Linux AT-SPI providers.
- Implement the ntfy approval callback and bind approvals to action digests.
- Add a production audit sink with external hash anchoring.
- Compile recorded trajectories into parameterized skills automatically.
- Add window identity/focus binding before same-machine input execution.
- Add continuous integration across supported Python versions and operating
  systems.

Until those items are complete, PSOperator should be evaluated as a well-tested
security architecture starter, not an unattended production RPA system.
