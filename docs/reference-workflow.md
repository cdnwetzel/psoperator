# Reference workflow (R-304) and pilot platform decision

**Status:** v1 fixture built and probed live; v1 and v2 tasks specified; nothing
runs them yet. Recorded 2026-10-27. This is also the pilot-platform decision
note that v0.3 requires before implementation.

## Pilot platform

- **OS:** Linux, AT-SPI accessibility, on a work node's virtual X display (Xvfb
  `:99` with openbox), the same display the deployed observer service captures.
- **Toolkit:** GTK 3. Its AT-SPI tree is complete and stable. Tk exposes no
  AT-SPI tree on Linux, and Electron exposes only part of one, so neither can
  serve the element-only service path (`docs/service-loop.md`).
- **Planner lane:** a small local text model (the work node has an 8 GB GPU).
  Stage 2's probe tests whether it is good enough before the loop is built.

## Why two variants

v1 is the smallest task with an exact pass and fail, used to prove the service
path end to end. v2 adds what v1 cannot exercise: several fields, replacing
existing text, reading back what was typed, and a commit that needs approval. A
loop that passes v1 and fails v2 has only proven the trivial case.

## v1 — temperature converter

**Fixture:** `examples/fixtures/tempconv_form.py`, with its contract in
`psoperator/fixtures/tempconv.py`. It is a GTK port of the Tkinter converter
that the violoop harness drove by pixels, with the same layout and output: a
`Value` entry, `C to F` / `F to C` radio buttons (default `C to F`), a `Convert`
button, and a result shown to one decimal or as `error`.

The result label republishes its **accessible name** on every Convert
(`Result: 100.0`). A snapshot element carries the accessible name, not the
widget's text, so this is how the result reaches attested evidence.

**Live probe (work node, 2026-10-27):** with the fixture open on `:99`, AT-SPI
and the observer service both reported every control as an `a11y` element:

| role | accessible name |
| --- | --- |
| `frame` | `TempConv` |
| `text` | `Value` |
| `radio button` | `C to F` |
| `radio button` | `F to C` |
| `label` | `Result:` |
| `button` | `Convert` |

The name change after Convert has not yet been observed live; Stage 2 checks it.

**Task**

- **Start:** the fixture is open on the observer's display, with the entry
  empty and `C to F` selected. Exactly one `TempConv` window is open.
- **Goal:** "Convert 212 degrees Fahrenheit to Celsius."
- **Expected steps:** about 4–5 (focus `Value`, type `212`, select `F to C`,
  press `Convert`, finish). Budget: 8.

**Pass**, all of:

1. A fresh attested snapshot taken after the last action contains exactly one
   result label, and it reads `Result: 100.0` (`read_result`). The loop checks
   this itself before exiting `0`; a `done` from the planner is a claim, not
   evidence.
2. Every input action was bound to an element of the attested snapshot it was
   planned from.
3. The audit chain verifies (`psoperator audit-verify`).
4. The run stayed within the step budget.

**Fail**, each with a nonzero exit:

| what happened | what the evidence shows |
| --- | --- |
| converted the wrong way | `Result: 413.6` |
| typed the value twice (the violoop `100100` problem) | `Result: 117877.8` |
| typed something non-numeric | `Result: error` |
| never pressed Convert | `Result:` |
| two windows open | two result labels; `read_result` refuses to pick one |
| planner said `done` with any result above | loop's own check fails |
| kill switch engaged mid-run | the next step is `KILL_SWITCHED` |
| empty snapshot | `fail` without a model call |
| step budget exhausted | no passing result within 8 steps |

All v1 actions are T1, so v1 needs no approval path.

## v2 — invoice entry

**Fixture:** the existing `examples/fixtures/invoice_form.py`. It has four named
entries (`Vendor`, `Invoice Number`, `Date`, `Invoice Total`), a `Submit`
button, and the window title `Invoice Entry`. It opens pre-filled with the demo
invoice.

**Task**

- **Start:** the fixture is open with the demo invoice pre-filled.
- **Goal:** replace all four fields with a different invoice (named in the
  goal), then submit.
- **Expected steps:** about 10–14. Each field is focused, its old text replaced
  rather than appended to, and then the form is submitted.

**What v2 adds over v1, and what it needs first:**

1. **The entry's text must be in the snapshot.** Today an element carries its
   accessible name (`Vendor`) but not its contents, so neither the planner nor
   the checker can see what a field holds. Without that, the planner cannot
   tell a filled field from an empty one, which is how double typing happens,
   and the checker cannot verify the fields. This needs a perception change:
   read the AT-SPI text value into the element. It is part of R-303.
2. **Replacing text, not appending.** The fixture is pre-filled, so typing
   alone fails. Either the planner selects all (`ctrl+a`) before typing, or
   `type` into a bound element replaces its contents. This is decided when the
   executor gains focus handling (R-306 step 3).
3. **Submit is the commit and needs approval.** The pilot policy adds a T2 rule
   for `submit`. Under the services, T2 approval fails closed today: the CLI
   approval has no console, and the ntfy approval is a stub. So v2 runs in two
   phases.

**Pass, phase A** (before an approval path exists):

1. A fresh attested snapshot shows all four fields holding exactly the target
   values.
2. The Submit request is `DENIED` for want of approval, and the run exits with
   the distinct "needs approval" code.
3. The fixture recorded no submission.
4. The audit chain verifies.

**Pass, phase B** (after an approval path exists): the operator approves the
field-level preview (`field_rows`). Submit executes, the fixture's record
equals the target invoice, and exactly one submission is recorded. The fixture
gains a `--record PATH` option for this, so phase B has a checkable artifact.

**Fail:** any field wrong or partly appended to, a submission in phase A, a
second submission, or any v1 failure class.

## Order of work

1. Stage 1 hardening: service-side enforcement of allowed kinds and element
   binding (independent of this document).
2. Stage 2 go/no-go probe on v1: the planner model, given a live v1 snapshot
   and the goal, proposes the right first actions.
3. R-306 loop, driving v1 to pass, first in dry-run (admission and audit only;
   dry-run cannot change the result), then with real input under supervision.
4. Entry text in the snapshot (R-303), then v2 phase A.
5. An approval path, then v2 phase B.
