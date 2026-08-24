"""PSOperator — fully-local, cross-platform desktop-automation agent (proof of concept).

Security invariant (enforced by layout, not by convention alone):

* ``psoperator.runtime`` OBSERVES and ASKS. It never imports an input-injection
  library (pyautogui / pynput controllers).
* ``psoperator.gatekeeper`` DECIDES. It is the only package allowed to touch
  OS input devices, and only behind an auditable ``request_action()`` call.
* ``psoperator.gatekeeper.audit`` RECORDS. Every decision lands in an
  append-only, SHA-256 hash-chained JSONL log.
"""

__version__ = "0.1.0"
