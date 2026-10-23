"""Runtime: the observe->think->act->verify loop.

SECURITY INVARIANT: nothing in this package may import an input-injection
library (pyautogui, pynput controllers). The runtime ASKS the gatekeeper;
only psoperator.gatekeeper may touch OS input devices.
"""
