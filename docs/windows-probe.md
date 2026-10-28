# Windows probe: results

Step 2 of `docs/pilot-charter.md`, run on the first Windows endpoint on
2026-10-27 and 2026-10-28 with a synthetic test record. It records counts,
timings and geometry only. Probe output, screenshots and the scripts that
touched on-screen text stay outside the clone.

**Verdict: go with Win32 binding plus OCR reading.** Element identity comes
from the native window tree. Field values are read by OCR inside the field's
exact rectangle. The consequences are in the charter.

## Setup

- One monitor, 96 DPI (100 % scaling). The display was 1500×938 for the first
  UI Automation pass and 1408×671 after the session was resized; every later
  result is at 1408×671.
- The application is a single-window wxWidgets client. It is not DPI aware,
  which is harmless at 100 %.
- Input sent: two Escape keys, menu digits, typing a synthetic record key,
  Enter to advance its notices, and screen-selector digits. Each step was
  approved by the operator first. Before every key the probe checked that
  the application owned the foreground window, and before typing it checked
  that focus was on the intended control. No field was edited.

## UI Automation is not usable for this application

| | Notepad (control) | the application |
| --- | --- | --- |
| one property read, mean | 0.2–0.5 ms | ~110 ms |
| one node's children, mean | 5 ms | 0.2–4 s |
| one level, cached, median / max | 1 ms / 14 ms | 222 ms / 15.9 s |
| whole window tree | 45 elements in 0.1 s | 59–75 elements in 30–90 s |

The slowness is the application's UIA provider, not the machine. A single
cached subtree query fails with `0x80040201` (provider timeout), one subtree
usually times out, and the element count varies between walks.
`SnapshotBuilder(WinAutoA11y(), NullOCR())` ran on Windows without a code fix
but took **124 s** for one snapshot, because `WinAutoA11y` walks the whole
desktop with about eight cross-process calls per node.

The UIA walks happened to run on the search screen, which has one Edit, so
they understated the form. The Win32 view below supersedes them.

## The Win32 window tree is complete and fast

`Desktop(backend="win32")` and plain `EnumChildWindows` read the whole window
in about 0.01 s.

The record's opening screen, a scrolled form:

| class | count | notes |
| --- | --- | --- |
| `Edit` | 64 | the fields; 17 rows |
| `wxWindowClassNR` | 204 | small panels; one sits directly left of each Edit |
| `Button` | 16 | a fixed button bar, the same on every screen |

The other screens of the record, reached through its screen selector, have
the same build: 45–68 Edits each and the same button bar.

What each window carries:

- **Buttons:** the Win32 text is the drawn caption (15 of 16 equal to OCR).
- **The panel left of each Edit:** its Win32 text is an internal name, not the
  drawn label (0 of 64 equal to OCR). The visible labels are painted on the
  background and have no window.
- **Edits:** Win32 returns no text for any of them, even text the probe had
  just typed. Neither tested Win32 path (`WM_GETTEXT`, pywinauto's
  `window_text()`) returned field values; OCR read values in 40 of 64.
- **Control ids:** negative and allocated at runtime. 0 of 64 matched between
  two openings of the same screen.

## Identity that holds

Matching each Edit to its left panel by the panel's internal name (compared as
a hash) and both rectangles gave **64 of 64 identical** across three openings
of the record's opening screen, including one after an application restart.
Control ids never matched.

A whole-screen signature (every window's class, rectangle and internal name)
is **not** stable: the same screen gave different signatures depending on how
it was reached, because opening some screens moves focus into a table.
Identity is therefore per field, verified at each action, not per screen.

## Coordinates

At 96 DPI on one monitor, window rectangles from Win32, UI Automation and the
`MSSCapture` frame agree; a maximised window's -8 px border is the only
overhang. Other scaling factors and more than one monitor are untested
(roadmap R-303).

## Things the probe ran into

- **Another window can cover the application.** A maximised terminal sat in
  front of it during one pass, so the OCR of that pass read the terminal. Any
  capture or input must first check that the application is on top at the
  target point, not only that it exists.
- **Some screens move keyboard focus when they open.** A key meant for the
  screen selector would have gone into a table. Focus must be checked before
  every key.
- **Windows reuses process ids.** A restarted application came back with the
  same pid; check process start time, not only the pid.
- **The `perception` extra does not install `onnxruntime`,** which RapidOCR 2.x
  needs. Without it `RapidOCRProvider()` raises `ImportError`. The probe
  installed it by hand.

## Windows test baseline

On Python 3.13.17, with and without `onnxruntime`: **489 passed, 19 failed,
14 skipped**; `ruff check` is clean.

- 17 failures in `tests/test_attestation_gate.py`: `AttestationGate` refuses
  persistent gate state on Windows by design, because it cannot verify file
  ownership there. Porting that check is roadmap D-01.
- `tests/test_invoice_fixture.py::test_record_refuses_a_removed_or_replaced_file`:
  Windows will not delete a file that is still open.
- `tests/test_invoice_fixture.py::test_creating_a_record_at_an_invalid_path_is_an_error[bad\ud800.jsonl]`:
  Windows accepts a lone surrogate in a file name.
- The 14 skips are POSIX owner-only file-permission tests.

No refusal was weakened to make a test pass.
