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
  real data, the audit must record control identity (for this application,
  the field identity in the probe consequences below) rather than on-screen
  text. Synthetic data makes the test phase safe, not the
  design.
- **Isolation is checked, not assumed.** Before the first real input, confirm
  that the endpoint cannot reach production systems through the network, shared
  credentials or synced folders.
- **The kill switch reaches every service** on the endpoint through one shared
  path, as on the Linux bench.

## Order of work

1. **Endpoint setup.** Tools are installed over SSH; per-user setup and the
   clone happen in the desktop session (`docs/windows-handoff.md`).
2. **UI Automation probe** of the real application with a test record open.
   It answers whether fields and buttons have usable names and automation ids.
   **Done 2026-10-28; verdict: go with Win32 binding plus OCR reading**
   (`docs/windows-probe.md`). UI Automation is too slow on this application
   to use. The native Win32 window tree is complete and fast, and a field is
   identified by the internal name and rectangle of the panel beside it,
   which held across restarts. Control ids change on every opening. The
   tested Win32 paths returned no field values; OCR read them. Navigation was
   driven by keystrokes, each step approved by the operator; the operator's
   manual for those keystroke sequences stays private, like the denylist.
3. **Windows attestation port** (roadmap D-01, promoted into the pilot): the
   observer, attestation key and frame-hash contract on the Windows capture
   path.
4. **R-306 loop**, proven on the Linux bench, then run on the endpoint in
   dry-run.
5. **A reference task on the real application**, with exact pass and fail from
   attested evidence, first read-only, then with supervised real input.
6. Approval path with an attested preview, then commit-like actions.

## Consequences of the probe verdict

- **A new bound-target kind in the gatekeeper.** A target is a Win32 field
  (process, window class path, the internal name of its label panel, and its
  rectangle) or an OCR box, bound to the hash of the frame it was seen in.
  The gatekeeper admits input only against a target bound that way. This is a
  separate, test-first PR after D-01, because the frame hash it binds to is
  the Windows attestation contract. The field identity it binds is read by
  `psoperator/perception/win32_fields.py`: read-only, no window text or
  field values, the label panel's internal name kept only as a SHA-256. The
  bound-target PR's tests must hold it to these requirements:
  1. **Before any capture or input**, the application is the foreground
     window **and** owns the topmost window at the target point
     (`WindowFromPoint`); otherwise refuse, naming the blocking process.
     Negative control: a test window on top.
  2. **Identity uses window-relative rectangles** (relative to the
     top-level window). Screen rectangles are used only for acting, so
     moving or restoring the window does not break identity. (Done in the
     provider.)
  3. **A field is a valid target only if its rectangle lies inside the
     visible client area of its scrolling parent**: a scrolled-out Edit
     still reports itself visible.
  4. **Process identity includes the process start time**, not only the
     image name and pid, since Windows reuses pids. (Done in the provider.)
  5. **The audit records identity, the frame hash and the rectangles**,
     never text.

  The gate (`psoperator/gatekeeper/bound_target.py`, entry point
  `Gatekeeper.request_bound_key`) meets all five and adds an **allow-list**:
  a key is admitted only on a menu path explicitly listed as read-only, only
  the key listed for that step, and only when the screen's complete
  signature matches the step's expected one and none of its recorded
  neighbouring screens (every step must record at least one, such as the
  screen one wrong digit away). The signature is structure, never text:
  every visible Edit's position, every label-class caption on screen as a
  hash and position (so menus without fields are told apart), every
  labelled field's hash and position, dialogs and focus. The gatekeeper does
  not take the screen from the caller: its observer, clock, allow-list, the
  application it applies to and the one main window and process instance it
  may send to are fixed at construction. A request carries only the key, a
  path and step within the allow-list, and the target; it is read once, and
  the values checked are the values executed. The gatekeeper observes (the
  foreground window, the top-level window at the focused control, keyboard
  focus, menu and capture modes, dialogs, the window tree) before checking
  and again immediately before sending; any change, or a failed read,
  refuses; the kill switch is checked again at the last moment. The audited
  identity is built from that observation. Refusals are audited with fixed
  codes; with `bound_input_only`, every kind of device input (clicks, typing,
  keys, scrolling, dragging) that bypasses the gate is refused, whatever the
  kill switch reads after its first check. An empty allow-list refuses
  everything. The real allow-list, the application map and its dangerous
  paths are private configuration, never in this repository; the repository
  holds only the mechanism, tested with made-up paths.
- **The audit logs identity, never text:** the field's identity and
  rectangle, the OCR box and the frame hash. It never logs OCR text, field
  values or window text.
- **`WinAutoA11y` must be scoped to the target window.** It walks the whole
  desktop today; one snapshot took 124 s. That fix is its own test-first PR.
- **Every key is preceded by two checks:** the application is the foreground
  window and is on top at the target point, and keyboard focus is on the
  bound field. Some screens move focus when they open, and another window
  covered the application during the probe. This is R-301 on Windows.
- **The `perception` extra must install `onnxruntime`,** which RapidOCR 2.x
  needs and does not pull in. That fix comes with the OCR reading path. The
  test suite must give the same results with and without the optional OCR
  packages installed.

## Open decisions

- Where the planner model runs: on the endpoint, or on a fleet node reached
  over the LAN.
- How dx reaches PSOperator on Windows. `dx-bridge` is Linux-only today; either
  port it or keep dx on Linux and drive the endpoint remotely. This is decided
  at the dx integration step, not before.
- When and under what controls real data may be used.
