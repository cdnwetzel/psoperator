"""Reference fixtures for the supervised vertical slice (R-304).

``tempconv`` is the v1 task (one exact result) and ``invoice`` the v2 task
(several fields, a commit that needs approval); see
``docs/reference-workflow.md``.

The pure data contracts live here so the fixture UI (``examples/fixtures/``) and
the demo harness that reviews it share one source of truth for field names,
window identity, and the field-level preview. Importing this package pulls in no
GUI toolkit; the GTK app imports ``gi`` itself.
"""
