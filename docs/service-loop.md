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
   only the snapshot's element list, never pixels, and `LocalElementPlanner` may
   only target an element id from that list. On the work node the observer
   reported a 1920×1080 frame with **0 elements**:
   - the virtual display had no application open, so AT-SPI had nothing to report;
   - RapidOCR (`psoperator[perception]`) is not installed, so the OCR fallback is
     `NullOCR`.

   With an empty list the element planner can only return `fail`.
3. **The two paths use different planners.** `AgentLoop` sends the screenshot to
   a vision model and accepts coordinate actions. The service path sends element
   metadata to a text model and expects element-bound actions. Swapping the
   script changes the planner contract as well as the transport.

So switching dx now would turn every GUI task into an immediate `fail`. It would
be no safer and no more useful.

## Why this is a redesign, not a flag

The service path's planner contract is deliberate: an untrusted planner never
receives pixels or a capture backend, and an element-bound action lets the
gatekeeper check its target against the attested snapshot (`REJECTED_TARGET`).
That is the property v0.2 bought. Bolting `AgentLoop` onto the services by
passing screenshots to the planner would reopen what R-201/R-203 closed. So the
loop has to be rebuilt around the element contract, and perception has to supply
enough elements for that contract to work.

## Proposed fix

**R-306 — Service-mode agent loop** (v0.3, needed by the R-304 reference workflow):

1. **A service loop** (`psoperator/runtime/service_loop.py`, CLI
   `psoperator run --task … --max-steps N`):
   - Each step calls `ObserverClient.observe()`, then `planner.plan(snapshot, goal, history)`, then sends the request to the gatekeeper over IPC.
   - It stops on `done`/`fail`, on `KILL_SWITCHED`, `REJECTED_STALE` or `REJECTED_TARGET`, at the step budget, or when the observer is unavailable.
   - The loop holds no key, no secret and no executor. Real versus dry-run input is decided only by the executor service's backend, never by a client flag.
   - The exit code and a one-line summary per step mirror `run_agent.py`, so callers can swap with no output parsing changes.
2. **An element planner that can finish a task.** Give `LocalElementPlanner`:
   - the step history;
   - the full action vocabulary: `type` and `key` into a target element, `wait`, `done` and `fail`;
   - a bounded element list.

   It keeps the rule that it never invents an id.
3. **Perception that sees something on Linux** (part of R-303):
   - Install `psoperator[perception]` (RapidOCR) where the observer runs.
   - Confirm that AT-SPI sees applications started on the observer's display. They must share its D-Bus session and have accessibility enabled.
   - Add an observer health field for the a11y and OCR backends in use, so "0 elements because nothing is wired" can be told apart from "0 elements because the screen is empty".
4. **dx switches last.** `launch_gui_task` calls `psoperator run` instead of the
   example script. It drops its `real_input` flag for this path and reports the
   executor's mode instead. The in-process path stays available only as an
   explicit dev mode.

**Acceptance:**
- On the work node, a task against a test application opened on the virtual display completes through the three services in dry-run, with audit evidence for every step.
- `psoperator kill` stops it mid-task.
- An empty snapshot ends the run with a clear `fail`, not a hang.

**Considered and not chosen:**
- Sending pixels to a vision planner across the boundary, with the gatekeeper mapping coordinates to elements. It may be needed later for applications with no accessibility tree and no readable text, and would get its own design note.
- Keeping the in-process loop and documenting the bypass, which leaves v0.2's boundary unused by the only real caller.

## Until then

dx GUI runs keep using the in-process loop. Since 2026-10-27 that loop shares the
deployed kill-switch path, so `psoperator kill` stops it, but it has none of the
other v0.2 protections. Switching the executor service to real input does nothing
for dx until step 4 lands.
