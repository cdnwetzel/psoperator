# Service-mode agent loop (R-306 proposal)

**Status:** proposed, not started. Recorded 2026-10-27, when the first deployment
of the three services showed that nothing could use them for a real task.

## The finding

The v0.2 trust boundary is built and deployed: the observer, gatekeeper and
executor run as separate supervised services on a work node, and the gatekeeper
admits only attested observer envelopes. But the only multi-step agent,
`examples/run_agent.py` (`AgentLoop`), does not use any of them. It builds its own
capture, an in-process `Gatekeeper` and its own executor, so every task it runs
skips the R-203 envelope check, the separate executor, and the IPC secret on the
gatekeeper → executor hop. dx's `launch_gui_task` calls exactly that script.

The obvious fix, pointing dx at `examples/run_isolated.py`, does not work today:

1. **One action, not a task.** `run_isolated.py` observes once, plans once,
   submits one action and exits. It has no loop, no step budget, no history and
   no stop condition. A task like "open the editor and type hello" needs several
   steps.
2. **The planner has nothing to aim at.** Across the boundary the planner sees
   only the snapshot's element list, never pixels. `LocalElementPlanner` checks
   any element id it is given against that list, but today it also accepts a
   coordinate-only answer; mandatory binding is part of the proposal below. On
   the work node the observer
   reported a 1920×1080 frame with **0 elements**:
   - the virtual display had no application open, so AT-SPI had nothing to report;
   - RapidOCR (`psoperator[perception]`) is not installed, so the OCR fallback is
     `NullOCR`.

   With an empty list there is nothing valid to target. `LocalElementPlanner`
   still calls the model, and if the model names an id the snapshot lacks, the
   planner raises `ValueError`. `run_isolated.py` catches only
   `ObserverUnavailable`, so the run ends in a traceback rather than a clean
   `fail`.
3. **The two paths use different planners.** `AgentLoop` sends the screenshot,
   together with the element list, to a vision model. It prefers element ids but
   also accepts coordinate actions. The service path sends element metadata
   only, to a text model. Swapping the script changes the planner's inputs as
   well as the transport.

To be precise about what is bypassed: `run_agent.py` still applies the
gatekeeper's freshness, grounding, risk, approval and audit checks, but it does
so in-process. What it skips is the service boundary: R-203 envelope
authentication, the separate executor, and the IPC secret. Switching dx to
`run_isolated.py` would restore that boundary but lose multi-step orchestration:
a one-action task can still succeed, but anything longer cannot. Its exit code
is also unreliable, because the script checks only the response's `ok` field,
which is true for denied and failed decisions as well.

## Why this is a redesign, not a flag

The service path's planner contract is deliberate: an untrusted planner never
receives pixels or a capture backend. It works from attested element metadata,
so the gatekeeper can check an element-bound action's target against the signed
snapshot (`REJECTED_TARGET`). `AgentLoop` gives a vision model the screenshot as
well as the element list, and takes coordinate answers when the model offers
them. Pixels alone would not stop element binding, but they widen what an
untrusted planner sees, and the coordinate fallback is what lets an action skip
binding. R-306 therefore keeps the planner on element metadata and makes
binding mandatory at the gatekeeper service (step 3). The loop has to be
rebuilt around that contract, and perception has to supply enough elements for
it to work.

v0.2 itself still permits coordinate fallback (an unbound click inside the
frame) and unbound `type`/`key`. Making element binding mandatory on the
service path is a tightening that R-306 adds, not a property v0.2 already has.

## Proposed fix

**R-306 — Service-mode agent loop** (v0.3, needed by the R-304 reference workflow):

1. **A service loop** (`psoperator/runtime/service_loop.py`, CLI
   `psoperator run --task … --max-steps N`):
   - Each step calls `ObserverClient.observe()`, then `planner.plan(snapshot, goal, history)`, then sends the request to the gatekeeper over IPC.
   - It stops on every outcome other than an executed or dry-run step:
     - `done`, `fail`, `KILL_SWITCHED`, `REJECTED_STALE`, `REJECTED_TARGET`, `DENIED` and `EXECUTION_FAILED`;
     - an envelope rejection (`ok: false` with no decision);
     - a gatekeeper connection failure, timeout or malformed response;
     - the observer being unavailable;
     - the step budget running out.
   - It never retries or resubmits:
     - A denied action must not come back without a new approval (R-302).
     - After a failed execution, or a request whose response was lost, the outcome is unknown until a fresh observation, so the run ends and says so.
     - `ok: true` means only that a decision was made; the loop reads `decision.kind`.
     - A planner error (for example an invented id) ends the run as `fail`, never as a traceback.
   - Exit code `0` is reserved for `done`. `fail` and every other stop above exit nonzero, with a distinct code for "outcome unknown". This deliberately differs from `run_agent.py`, which treats `fail` as finished and exits `0`. The one-line-per-step summary stays compatible.
   - The kill switch blocks the *next* step: the gatekeeper checks it before approval and execution. It does not interrupt input already being sent. Acceptance tests that guarantee and nothing stronger.
2. **An element planner that can finish a task.** Give `LocalElementPlanner`:
   - the step history;
   - the action subset R-306 supports: `click`, `double_click` and `right_click` on an element; `type` and `key` into an element; and `wait`, `done` and `fail`;
   - a bounded element list;
   - a guard that returns `fail` without calling the model when the snapshot has no elements, and a check that a coordinate-only answer is refused, not only an invented id.

   It keeps the rule that it never invents an id.
3. **The gatekeeper service enforces the contract; the prompt does not.** A
   compromised client can send anything the parser accepts, so every rule is
   checked in `GatekeeperService`, with adversarial tests:
   - **Allowed kinds only.** It rejects `scroll` and `drag` outright until a reference workflow needs them. The parser, gatekeeper and executors all accept them today.
   - **Element binding is mandatory.** It rejects any input action (`click`, `double_click`, `right_click`, `type`, `key`) that does not name an element in the attested snapshot. Today `type` and `key` pass with no target, and a coordinate-only click passes if it lands inside the frame.
   - **Trusted target resolution and focus.** For clicks the gatekeeper already resolves coordinates from the attested element. For `type` and `key` it must resolve the target as well and send it to the executor over the authenticated hop. Today `RemoteExecutor` forwards the action without its snapshot, and keyboard execution ignores the element id. The executor focuses that target and refuses if focus cannot be established or has moved. Only accessibility elements can take keyboard input; OCR text boxes are not focusable controls. This depends on R-301's window and focus checks.
   - **Attested metadata drives risk.** Caller-supplied context may add risk keywords but never replace the attested label. A probe showed an element-bound "Delete" click dropping from `denied` to `dry-run` when the client sent `target_text: "safe"`. That is fixed separately on the current gatekeeper, ahead of R-306.

   The in-process loop keeps its current rules.
4. **Perception that sees something on Linux** (part of R-303):
   - Install `psoperator[perception]` (RapidOCR) where the observer runs.
   - Confirm that AT-SPI sees applications started on the observer's display. They must share its D-Bus session and have accessibility enabled.
   - Add an observer health field for the a11y and OCR backends in use, so "0 elements because nothing is wired" can be told apart from "0 elements because the screen is empty".
5. **dx switches last.** `launch_gui_task` calls `psoperator run` instead of the example script, after these prerequisites:
   - The planner runs under its own account, per `docs/deployment-isolation.md`. Separate service processes are not enough on their own: "holds no key" must mean "cannot read one".
   - A check from the planner account shows it cannot read the attestation key or the IPC secret, and cannot reach the executor directly.
   - dx drops its `real_input` flag for this path and reports the executor's mode instead.
   - The in-process path stays available only as an explicit dev mode.

**Acceptance**, in three layers. Dry-run leaves the application unchanged, so it cannot prove a task finished:
- **Simulated (CI):** a deterministic multi-step task runs through the three services, with a fake executor that updates a fake application, so later observations reflect earlier actions. It covers:
  - `done` exits `0`;
  - an empty snapshot exits nonzero with `fail`, without calling the model;
  - each stop condition above other than `done` exits nonzero, and none resubmits;
  - the kill switch blocks the next step;
  - unbound input, `scroll`/`drag`, and caller context that tries to lower risk are all rejected or held at the attested tier.
- **Live dry-run (work node):** a task against a test application on the virtual display is admitted step by step through the services, with audit evidence for every step.
- **Supervised real input (R-304):** the reference workflow completes with real input under supervision, with R-302 postcondition evidence.

**Considered and not chosen:**
- Sending pixels to a vision planner across the boundary, with the gatekeeper mapping coordinates to elements. It may be needed later for applications with no accessibility tree and no readable text, and would get its own design note.
- Keeping the in-process loop and documenting the bypass, which leaves v0.2's boundary unused by the only real caller.

## Until then

dx GUI runs keep using the in-process loop. Since 2026-10-27 that loop shares the
deployed kill-switch path, so `psoperator kill` stops it. It keeps the
in-process gatekeeper checks but not the v0.2 service boundary. Switching the
executor service to real input does nothing for dx until step 5 lands.
