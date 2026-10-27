# Pilot charter

**Status:** decided 2026-10-27. This is the pilot decision note that `v0.3`
requires before implementation (roadmap §6). It replaces the platform choice in
`docs/reference-workflow.md`.

## Purpose

PSOperator's first real job is to drive a **Windows desktop application that has
no API**: open a record, read and change fields, commit, and report what it
did. The goal is to do this **unattended eventually**. Until the evidence
supports that, it runs supervised.

## Platform order

1. **Windows desktop applications** (UI Automation). This is the pilot.
2. Web and Electron applications, later.
3. Linux desktop applications, later. The Linux work node and the GTK fixtures
   in `docs/reference-workflow.md` stay as a **test bench for the safety loop**.
   They prove the loop works, not that the use case does.
4. macOS: not planned.

## Test target

- A Windows endpoint the operator controls, running a **fully local copy** of
  the target application. It is not production, and nothing on it may reach
  production.
- The application holds **synthetic test records only**. Real data is a
  long-term goal and needs its own decision (below).
- The repository never names the application, its records, the endpoint, or
  the organisation. Probe output that contains on-screen text is never
  committed.

## What "unattended eventually" requires

These hold from the start, so they never have to be retrofitted:

- **Approval is core.** Any commit-like action (Submit, Save, Delete) needs an
  approval path whose preview is built from attested values, as in
  `docs/reference-workflow.md` v2. Unattended operation later means narrowing
  what needs approval, never removing the gate.
- **The audit log carries no record data.** Today a decision records the target
  element's label. On a real form that label can be a person's name. Before any
  real data, the audit must record control identity (role, automation id)
  rather than on-screen text. Synthetic data makes the test phase safe, not the
  design.
- **Isolation is checked, not assumed.** Before the first real input, confirm
  that the endpoint cannot reach production systems through the network, shared
  credentials or synced folders.
- **The kill switch reaches every service** on the endpoint through one shared
  path, as on the Linux bench.

## Order of work

1. **Endpoint setup.** Tools are installed over SSH; per-user setup and the
   clone happen in the desktop session (`docs/windows-handoff.md`).
2. **Read-only UI Automation probe** of the real application with a test
   record open. It answers whether fields and buttons have usable names and
   automation ids. No input is sent. If the tree is poor, the next step is OCR
   or a fixture, decided from the evidence.
3. **Windows attestation port** (roadmap D-01, promoted into the pilot): the
   observer, attestation key and frame-hash contract on the Windows capture
   path.
4. **R-306 loop**, proven on the Linux bench, then run on the endpoint in
   dry-run.
5. **A reference task on the real application**, with exact pass and fail from
   attested evidence, first read-only, then with supervised real input.
6. Approval path with an attested preview, then commit-like actions.

## Open decisions

- Where the planner model runs: on the endpoint, or on a fleet node reached
  over the LAN.
- How dx reaches PSOperator on Windows. `dx-bridge` is Linux-only today; either
  port it or keep dx on Linux and drive the endpoint remotely. This is decided
  at the dx integration step, not before.
- When and under what controls real data may be used.
