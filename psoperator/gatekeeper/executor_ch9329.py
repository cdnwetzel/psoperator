"""CH9329 HID executor — Topology B (crash-cart / out-of-band mode).

In Topology B input never touches the agent machine's OS: an approved Action
is encoded into CH9329 serial protocol frames and written to a UART
(/dev/ttyUSB0 by default), where a CH9329 chip converts them into real USB
HID reports on the *target* machine. The gatekeeper boundary is unchanged —
this module lives in ``psoperator.gatekeeper`` and is only reachable through
``Gatekeeper.request_action(...)``.

Layout, deliberately testable without hardware:

* ``_to_abs_coords`` — pure pixel -> CH9329 absolute-coordinate scaling.
* ``build_frame`` / ``kbd_packet`` / ``mouse_abs_packet`` — pure protocol
  packet construction (frame = 0x57 0xAB 0x00 CMD LEN DATA... SUM, where
  SUM = sum(head..data) & 0xFF).
* ``Transport`` — anything with ``write(bytes)``/``close()``. Default is a
  lazily-imported pyserial ``Serial``; ``NullSerialTransport`` records frames
  for tests. No serial port is opened unless one is constructed.

pyserial is NOT a required dependency: it is imported lazily and a missing
install raises a clear error pointing at the ``ch9329`` extra. (The extra
also ships ``pych9329-hid``, vendor-side tooling useful for reconfiguring
the chip — e.g. moving it off its 9600-baud factory default — and for
interactive REPL debugging; the executor itself speaks the documented wire
protocol directly.)

Chip revisions: the wire protocol above is shared, but the *carrier* is not.
Published v1.6/v1.9 Mini-KVMs use a **CH9329** behind a CH340 USB-serial bridge
(``1a86:7523``) and enumerate as ``/dev/ttyUSB*``; newer units use a
**CH32V208** MCU (``1a86:fe0c``) which is native USB CDC and enumerates as
``/dev/ttyACM*``. Both speak the same frames — verified against the vendor host
application, whose chip-strategy interface declares no keyboard or mouse methods
at all — so this executor drives either. What differs is the port path and the
baud rate, which is why both are *detected from the device* rather than assumed.
Neither USB id is unique to the KVM (``1a86:7523`` is every CH340 adapter;
``1a86:fe0c`` is WCH's CDC id for the CH32V208 MCU), so ``port='auto'``
identifies the chip and names the port but refuses to open it: an explicit
port is the operator's assertion of what is behind that id, and the baud is
still derived from the identified chip. A read-only protocol probe is the
discriminator that would let ``auto`` open a port (psoperator #14).

Baud note: the CH9329 ships at **9600** baud; 115200 works only after the chip
has been reconfigured (vendor tool / SET_PARA_CFG). The CH32V208 is **fixed at
115200** and cannot be reconfigured at all. So ``baudrate`` must match the chip
in the box, not the one the config wishes for — hence :func:`resolve_baudrate`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from psoperator.runtime.actions import Action, ActionKind

# --------------------------------------------------------------------------
# Coordinate scaling (pure, unit-testable)
# --------------------------------------------------------------------------

#: CH9329 absolute-mouse reports use a 0..4095 coordinate space per axis.
ABS_MAX = 4095


def _to_abs_coords(x: int, y: int, w: int, h: int) -> tuple[int, int]:
    """Map a pixel coordinate on a ``w`` x ``h`` screen into CH9329's
    0..4095 absolute space. Out-of-screen pixels are clamped to the edge.

    Pixel (0, 0) -> (0, 0) and pixel (w-1, h-1) -> (4095, 4095).
    """
    if w < 1 or h < 1:
        raise ValueError(f"screen size must be positive, got {w}x{h}")
    cx = min(max(int(x), 0), w - 1)
    cy = min(max(int(y), 0), h - 1)
    return round(cx * ABS_MAX / max(w - 1, 1)), round(cy * ABS_MAX / max(h - 1, 1))


# --------------------------------------------------------------------------
# CH9329 wire protocol (pure packet construction, unit-testable)
# --------------------------------------------------------------------------

HEAD0, HEAD1, DEV_ADDR = 0x57, 0xAB, 0x00
CMD_SEND_KB_GENERAL = 0x02
CMD_SEND_MS_ABS = 0x04

BTN_LEFT, BTN_RIGHT, BTN_MIDDLE = 0x01, 0x02, 0x04

# USB HID modifier bits (left-hand variants)
_MODIFIERS = {
    "ctrl": 0x01,
    "control": 0x01,
    "shift": 0x02,
    "alt": 0x04,
    "option": 0x04,
    "win": 0x08,
    "cmd": 0x08,
    "command": 0x08,
    "meta": 0x08,
    "super": 0x08,
}

# USB HID usage IDs (page 0x07) for named non-character keys
_NAMED_KEYS = {
    "enter": 0x28,
    "return": 0x28,
    "esc": 0x29,
    "escape": 0x29,
    "backspace": 0x2A,
    "tab": 0x2B,
    "space": 0x2C,
    "caps_lock": 0x39,
    "capslock": 0x39,
    "print_screen": 0x46,
    "scroll_lock": 0x47,
    "pause": 0x48,
    "insert": 0x49,
    "home": 0x4A,
    "pageup": 0x4B,
    "page_up": 0x4B,
    "delete": 0x4C,
    "end": 0x4D,
    "pagedown": 0x4E,
    "page_down": 0x4E,
    "right": 0x4F,
    "left": 0x50,
    "down": 0x51,
    "up": 0x52,
    **{f"f{i}": 0x3A + i - 1 for i in range(1, 13)},
}

# ASCII chars that need shift held (US layout): char -> unshifted char
_SHIFTED = {
    "!": "1",
    "@": "2",
    "#": "3",
    "$": "4",
    "%": "5",
    "^": "6",
    "&": "7",
    "*": "8",
    "(": "9",
    ")": "0",
    "_": "-",
    "+": "=",
    "{": "[",
    "}": "]",
    "|": "\\",
    ":": ";",
    '"': "'",
    "~": "`",
    "<": ",",
    ">": ".",
    "?": "/",
}

_PUNCT = {
    "-": 0x2D,
    "=": 0x2E,
    "[": 0x2F,
    "]": 0x30,
    "\\": 0x31,
    ";": 0x33,
    "'": 0x34,
    "`": 0x35,
    ",": 0x36,
    ".": 0x37,
    "/": 0x38,
    " ": 0x2C,
}


def _char_to_hid(ch: str) -> tuple[int, int]:
    """ASCII char -> (modifier_mask, keycode). Raises on unsupported chars."""
    if len(ch) != 1:
        raise ValueError(f"expected a single character, got {ch!r}")
    if ch in _SHIFTED:
        return 0x02, _char_to_hid(_SHIFTED[ch])[1]
    if ch.isupper():
        return 0x02, ord(ch.lower()) - ord("a") + 0x04
    if "a" <= ch <= "z":
        return 0x00, ord(ch) - ord("a") + 0x04
    if ch == "0":
        return 0x00, 0x27
    if "1" <= ch <= "9":
        return 0x00, ord(ch) - ord("1") + 0x1E
    if ch in _PUNCT:
        return 0x00, _PUNCT[ch]
    if ch == "\n":
        return 0x00, 0x28
    raise ValueError(f"unsupported character for CH9329 typing: {ch!r}")


def _key_to_hid(name: str) -> tuple[int, int | None]:
    """Named key -> (modifier_mask, keycode); keycode is None for pure mods."""
    n = name.lower()
    if n in _MODIFIERS:
        return _MODIFIERS[n], None
    if n in _NAMED_KEYS:
        return 0x00, _NAMED_KEYS[n]
    if len(n) == 1:
        return _char_to_hid(n)
    raise ValueError(f"unknown key name: {name!r}")


def build_frame(cmd: int, data: bytes | list[int]) -> bytes:
    """One CH9329 frame: 57 AB 00 CMD LEN DATA... SUM (SUM = sum so far & 0xFF)."""
    payload = bytes(data)
    body = bytes([HEAD0, HEAD1, DEV_ADDR, cmd, len(payload)]) + payload
    return body + bytes([sum(body) & 0xFF])


def kbd_packet(modifier: int = 0, keycodes: list[int] | tuple[int, ...] = ()) -> bytes:
    """General-keyboard report: modifier byte, reserved byte, up to 6 keycodes."""
    keys = list(keycodes)[:6] + [0x00] * (6 - len(keycodes))
    return build_frame(CMD_SEND_KB_GENERAL, [modifier & 0xFF, 0x00, *keys])


def mouse_abs_packet(ax: int, ay: int, buttons: int = 0, wheel: int = 0) -> bytes:
    """Absolute-mouse report: mode 0x02, buttons, X/Y little-endian, wheel."""
    ax = min(max(ax, 0), ABS_MAX)
    ay = min(max(ay, 0), ABS_MAX)
    data = [
        0x02,
        buttons & 0xFF,
        ax & 0xFF,
        (ax >> 8) & 0xFF,
        ay & 0xFF,
        (ay >> 8) & 0xFF,
        wheel & 0xFF,
    ]
    return build_frame(CMD_SEND_MS_ABS, data)


# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------


@runtime_checkable
class Transport(Protocol):
    """Byte sink for CH9329 frames. ``serial.Serial`` satisfies this."""

    def write(self, data: bytes) -> int: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------
# Chip / port detection (pure enough to test; no port is opened here)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ChipProfile:
    """What a supported control chip needs from us, keyed by USB identity."""

    name: str
    #: Baud the chip is locked to, or ``None`` when it is configurable.
    fixed_baudrate: int | None
    #: Baud to use when the caller expressed no preference.
    default_baudrate: int
    #: Whether the USB identity alone is enough for ``port='auto'`` to open the
    #: port and write actuator frames to it. ``False`` means the id is shared
    #: with unrelated hardware, so the operator must name the port explicitly.
    auto_selectable: bool = True


#: USB identities we know how to drive. Both speak the same frame format; they
#: differ only in carrier, port class and baud. Keyed (vid, pid).
KNOWN_CHIPS: dict[tuple[int, int], ChipProfile] = {
    # CH9329 behind a CH340 USB-serial bridge — published v1.6/v1.9 hardware.
    # 1a86:7523 is the id of *every* CH340/CH341 serial adapter (the Linux
    # ``ch341`` driver binds it generically), so it proves a bridge is present,
    # not what sits behind it. Auto-selecting it could write HID frames into an
    # Arduino clone or a debug console. Fail closed: recognise it, never choose
    # it — the operator names the port.
    (0x1A86, 0x7523): ChipProfile(
        "CH9329", fixed_baudrate=None, default_baudrate=9600, auto_selectable=False
    ),
    # CH32V208 MCU, native USB CDC — newer hardware. 115200 only, not reconfigurable.
    # 1a86:fe0c is WCH's CDC id for the MCU, not one unique to the KVM: another
    # CH32V208 CDC firmware on the bench carries it too. Same rule — identify,
    # never select. A read-only CMD_GET_INFO probe is the discriminator that
    # would let ``auto`` open a port (psoperator #14); until it exists and is
    # verified on hardware, ``auto_selectable`` stays False for every profile.
    (0x1A86, 0xFE0C): ChipProfile(
        "CH32V208", fixed_baudrate=115200, default_baudrate=115200, auto_selectable=False
    ),
}

#: Sentinel accepted by ``port=`` meaning "find it from USB identity".
AUTO_PORT = "auto"


@dataclass(frozen=True)
class DetectedPort:
    device: str
    chip: ChipProfile


def _list_ports():
    """Lazily import pyserial's port enumerator. Same optional-dep contract as
    :func:`_open_serial`: a missing install is a clear error, never a silent
    empty list (an empty list would read as 'no device attached' and send the
    operator hunting cables for a packaging problem)."""
    try:
        from serial.tools import list_ports
    except ImportError as e:  # pragma: no cover - exercised via monkeypatch
        raise RuntimeError(
            "port auto-detection needs pyserial, which is not installed. "
            "Install it with: pip install -e .[ch9329]"
        ) from e
    return list(list_ports.comports())


def detect_hid_port(candidates=None) -> DetectedPort:
    """Find the attached HID-control chip by USB identity.

    Fails closed in both directions. Nothing attached is an error naming what
    *was* seen, so the operator can tell "wrong cable" from "wrong driver".
    **More than one match is also an error**: this is an actuator, and silently
    picking the first of two KVMs would inject keystrokes into whichever target
    happened to enumerate first. Ambiguity is for the operator to resolve with
    an explicit ``port=``, never for us to guess. And a match whose USB id is
    **not unique to this hardware** is reported, not chosen: identity alone does
    not prove there is a HID chip behind it. Today that is every known profile,
    so ``auto`` finds and names the port and the operator opens it explicitly.
    """
    ports = _list_ports() if candidates is None else list(candidates)
    matches = [
        DetectedPort(p.device, KNOWN_CHIPS[(p.vid, p.pid)])
        for p in ports
        if (p.vid, p.pid) in KNOWN_CHIPS
    ]
    if not matches:
        seen = (
            ", ".join(
                f"{p.device} ({p.vid:04x}:{p.pid:04x})"
                if p.vid is not None and p.pid is not None
                else f"{p.device} (no USB id)"
                for p in ports
            )
            or "no serial ports at all"
        )
        raise RuntimeError(
            "no supported HID-control chip found. Looked for "
            + ", ".join(f"{v:04x}:{p:04x} ({c.name})" for (v, p), c in KNOWN_CHIPS.items())
            + f"; saw: {seen}. "
            "(cable plugged into the HOST side? on Linux, is there a udev rule for it? "
            "the CH32V208 is CDC ACM and needs a rule on the 'tty' subsystem, "
            "not 'ttyACM' — see the README.)"
        )
    if len(matches) > 1:
        raise RuntimeError(
            "more than one supported HID-control chip attached: "
            + ", ".join(f"{m.device} ({m.chip.name})" for m in matches)
            + ". Refusing to choose — this backend actuates a target machine, so "
            "picking the wrong one types into the wrong computer. Pass an explicit "
            "port= to say which."
        )
    found = matches[0]
    if not found.chip.auto_selectable:
        vid, pid = next(k for k, v in KNOWN_CHIPS.items() if v is found.chip)
        raise RuntimeError(
            f"found a {found.chip.name} at {found.device} ({vid:04x}:{pid:04x}). That USB "
            "id identifies the serial chip, not the HID cable — unrelated hardware "
            "carries it too — so auto will not write actuator frames to it on "
            f"identity alone. If it is the HID cable, pass port={found.device!r} "
            "explicitly; the baud is still derived from the chip."
        )
    return found


def resolve_baudrate(chip: ChipProfile, configured: int | None) -> int:
    """Baud derived from the chip, not asserted by config.

    A chip with a fixed rate wins over any configured value — the CH32V208 is
    115200-only and cannot be reconfigured, so honouring a stored 9600 would
    produce a port that opens and then never speaks. Mismatches are surfaced by
    the caller rather than swallowed.
    """
    if chip.fixed_baudrate is not None:
        return chip.fixed_baudrate
    return chip.default_baudrate if configured is None else configured


def _identify(port: str) -> ChipProfile | None:
    """Best-effort chip lookup for an explicitly-given port. Returns ``None``
    when the port is not a recognised device (or cannot be enumerated at all) —
    an explicit port must keep working even if detection is unavailable."""
    try:
        for p in _list_ports():
            if p.device == port and (p.vid, p.pid) in KNOWN_CHIPS:
                return KNOWN_CHIPS[(p.vid, p.pid)]
    except RuntimeError:
        return None
    return None


def resolve_connection(
    port: str, baudrate: int | None
) -> tuple[str, int, ChipProfile | None]:
    """Turn a requested (port, baud) into the concrete pair to open.

    Kept separate from :func:`_open_serial` on purpose: resolution is decidable
    without hardware and is the part worth testing, while opening is the part
    that needs a real port. ``port='auto'`` detects by USB identity; an explicit
    port is still identified best-effort so a fixed-baud chip is honoured.
    """
    if port == AUTO_PORT:
        detected = detect_hid_port()
        port, chip = detected.device, detected.chip
    else:
        chip = _identify(port)
    baud = resolve_baudrate(chip, baudrate) if chip else (9600 if baudrate is None else baudrate)
    return port, baud, chip


def _open_serial(port: str, baudrate: int) -> Transport:
    """Default transport: pyserial. Lazy import guard — pyserial is optional.

    Takes an already-resolved port and baud (see :func:`resolve_connection`).
    """
    try:
        import serial
    except ImportError as e:
        raise RuntimeError(
            "CH9329Executor needs pyserial, which is not installed. "
            "Install it with: pip install -e .[ch9329]"
        ) from e
    baud = baudrate
    try:
        return serial.Serial(port, baud, timeout=0.05)
    except Exception as e:
        # Identify only on the failure path: the happy path has already resolved
        # the chip in resolve_connection, and re-enumerating every open to build
        # a message nobody sees is pure cost.
        chip = _identify(port)
        chip_note = (
            f"detected chip {chip.name}. "
            if chip
            else (
                "could not identify the chip on that port — if this is a newer "
                "Mini-KVM the control chip is a CH32V208 on /dev/ttyACM*, not a "
                "CH9329 on /dev/ttyUSB*; port='auto' names the port it finds. "
            )
        )
        raise RuntimeError(
            f"cannot open HID serial port {port!r} at {baud} baud: {e} "
            f"({chip_note}"
            "cable plugged into the HOST side? permissions — 'dialout' group for "
            "/dev/ttyUSB*, and a udev rule on the 'tty' subsystem for /dev/ttyACM*? "
            "a CH9329 still at its 9600-baud factory default?)"
        ) from e


class NullSerialTransport:
    """Test double: records every frame written; never touches hardware."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> int:
        self.frames.append(bytes(data))
        return len(data)

    def close(self) -> None:
        self.closed = True

    # convenience for assertions: decode recorded frames back to (cmd, data)
    def parsed(self) -> list[tuple[int, bytes]]:
        out = []
        for f in self.frames:
            if len(f) < 6 or f[0] != HEAD0 or f[1] != HEAD1:
                raise ValueError(f"recorded frame is not a CH9329 frame: {f.hex()}")
            cmd, ln = f[3], f[4]
            data = f[5 : 5 + ln]
            if sum(f[:-1]) & 0xFF != f[-1]:
                raise ValueError(f"recorded frame has a bad checksum: {f.hex()}")
            out.append((cmd, data))
        return out


# --------------------------------------------------------------------------
# Executor
# --------------------------------------------------------------------------


class CH9329Executor:
    """Real input injection into a *target* machine via a CH9329 HID chip.

    Same call contract as ``PynputExecutor``: the gatekeeper hands an
    approved Action to ``execute()``. Construct it only from the gatekeeper,
    only after operator opt-in (config ``executor_backend = "ch9329"``).
    """

    name = "ch9329"

    def __init__(
        self,
        port: str = AUTO_PORT,
        baudrate: int | None = None,
        screen_width: int = 1920,
        screen_height: int = 1080,
        transport: Transport | None = None,
        press_delay: float = 0.02,
    ) -> None:
        self._screen = (screen_width, screen_height)
        #: What was actually resolved — None when a transport was injected.
        self.port: str | None = None
        self.baudrate: int | None = None
        self.chip: ChipProfile | None = None
        if transport is not None:
            self._transport = transport
        else:
            self.port, self.baudrate, self.chip = resolve_connection(port, baudrate)
            self._transport = _open_serial(self.port, self.baudrate)
        self._press_delay = press_delay  # inter-report gap; 9600 baud is slow

    # ------------------------------------------------------------- helpers
    def _send(self, frame: bytes) -> None:
        self._transport.write(frame)
        if self._press_delay:
            time.sleep(self._press_delay)

    def _abs(self, x: int, y: int) -> tuple[int, int]:
        return _to_abs_coords(x, y, *self._screen)

    def _tap_button(self, x: int, y: int, button: int) -> None:
        ax, ay = self._abs(x, y)
        self._send(mouse_abs_packet(ax, ay, buttons=button))  # press
        self._send(mouse_abs_packet(ax, ay, buttons=0))  # release

    # ------------------------------------------------------------- Executor
    def execute(self, action: Action) -> str:
        k = action.kind
        if k in (ActionKind.CLICK, ActionKind.RIGHT_CLICK, ActionKind.DOUBLE_CLICK):
            button = BTN_RIGHT if k is ActionKind.RIGHT_CLICK else BTN_LEFT
            clicks = 2 if k is ActionKind.DOUBLE_CLICK else 1
            for _ in range(clicks):
                self._tap_button(action.x, action.y, button)
            button_name = "right" if button == BTN_RIGHT else "left"
            return f"clicked {button_name} x{clicks} at ({action.x}, {action.y})"
        if k is ActionKind.TYPE:
            for ch in action.text or "":
                mod, keycode = _char_to_hid(ch)
                self._send(kbd_packet(mod, [keycode]))  # press
                self._send(kbd_packet())  # release
            return f"typed {len(action.text or '')} chars"
        if k is ActionKind.KEY:
            mod = 0
            codes = []
            for name in action.keys:
                m, code = _key_to_hid(name)
                mod |= m
                if code is not None:
                    codes.append(code)
            self._send(kbd_packet(mod, codes))  # chord down
            self._send(kbd_packet())  # all up
            return f"pressed {'+'.join(action.keys)}"
        if k is ActionKind.SCROLL:
            amount = max(-127, min(int(action.amount or 0), 127))
            ax, ay = self._abs(action.x or 0, action.y or 0)
            self._send(mouse_abs_packet(ax, ay, buttons=0, wheel=amount))
            return f"scrolled {action.amount}"
        if k is ActionKind.DRAG:
            x0, y0 = self._abs(action.x, action.y)
            x1, y1 = self._abs(action.to_x, action.to_y)
            self._send(mouse_abs_packet(x0, y0, buttons=BTN_LEFT))  # grab
            self._send(mouse_abs_packet(x1, y1, buttons=BTN_LEFT))  # move held
            self._send(mouse_abs_packet(x1, y1, buttons=0))  # drop
            return f"dragged ({action.x},{action.y})->({action.to_x},{action.to_y})"
        if k is ActionKind.WAIT:
            time.sleep(min(action.seconds or 0.0, 30.0))
            return f"waited {action.seconds}s"
        return f"no-op for {k.value}"

    def close(self) -> None:
        self._transport.close()
