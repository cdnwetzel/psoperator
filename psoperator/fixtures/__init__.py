"""Reference fixtures for the supervised vertical slice (R-304).

The pure data contracts live here so the fixture UI (``examples/fixtures/``) and
the demo harness that reviews it share one source of truth for field names,
window identity, and the field-level preview. Importing this package pulls in no
GUI toolkit; the GTK app imports ``gi`` itself.
"""
