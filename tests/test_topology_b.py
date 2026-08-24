"""Topology B (crash-cart / out-of-band): UVC capture, CH9329 executor, wiring.

No real hardware is touched anywhere in this file: cv2 is stubbed in
sys.modules, and the CH9329 executor is fed a NullSerialTransport that only
records the protocol frames it would have written.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from psoperator.config import load_config
from psoperator.gatekeeper.approval import AutoApprove
from psoperator.gatekeeper.executor import DryRunExecutor
from psoperator.gatekeeper.executor_ch9329 import (
    CH9329Executor,
    NullSerialTransport,
    _char_to_hid,
    _to_abs_coords,
    kbd_packet,
    mouse_abs_packet,
)
from psoperator.gatekeeper.gatekeeper import DecisionKind, Gatekeeper
from psoperator.perception.capture import Frame, ScreenCapture
from psoperator.perception.capture_uvc import UVCCapture
from psoperator.runtime.actions import Action, ActionKind
from psoperator.runtime.freshness import FreshnessTracker

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
import run_crashcart  # noqa: E402


# --------------------------------------------------------------------------
# _to_abs_coords: pixel -> 0..4095 CH9329 absolute space
# --------------------------------------------------------------------------
class TestAbsCoords:
    def test_corners(self):
        assert _to_abs_coords(0, 0, 1920, 1080) == (0, 0)
        assert _to_abs_coords(1919, 1079, 1920, 1080) == (4095, 4095)

    def test_center(self):
        ax, ay = _to_abs_coords(960, 540, 1920, 1080)
        assert abs(ax - 2048) <= 1
        assert abs(ay - 2048) <= 2

    def test_clamping(self):
        assert _to_abs_coords(-50, -1, 1920, 1080) == (0, 0)
        assert _to_abs_coords(5000, 99999, 1920, 1080) == (4095, 4095)

    def test_odd_resolution(self):
        assert _to_abs_coords(0, 0, 1365, 767) == (0, 0)
        assert _to_abs_coords(1364, 766, 1365, 767) == (4095, 4095)
        ax, ay = _to_abs_coords(683, 384, 1365, 767)
        assert abs(ax - 2048) <= 4 and abs(ay - 2049) <= 4

    def test_degenerate_and_invalid_sizes(self):
        assert _to_abs_coords(0, 0, 1, 1) == (0, 0)  # no division by zero
        with pytest.raises(ValueError):
            _to_abs_coords(0, 0, 0, 1080)


# --------------------------------------------------------------------------
# pure packet construction
# --------------------------------------------------------------------------
class TestPackets:
    def test_keyboard_packet_matches_datasheet_example(self):
        # Documented CH9329 frame for pressing 'a' (vendor datasheet):
        # 57 AB 00 02 08 00 00 04 00 00 00 00 00 10
        assert kbd_packet(0, [0x04]) == bytes.fromhex("57ab000208000004000000000010")

    def test_keyboard_release_all_zeros(self):
        pkt = kbd_packet()
        assert pkt[3] == 0x02 and pkt[4] == 8
        assert pkt[5:13] == bytes(8)
        assert sum(pkt[:-1]) & 0xFF == pkt[-1]

    def test_mouse_abs_packet_layout(self):
        data = mouse_abs_packet(4095, 2048, buttons=0x01, wheel=-1)
        assert data[3] == 0x04 and data[4] == 7
        assert data[5] == 0x02  # absolute-mouse report id
        assert data[6] == 0x01  # left button
        assert data[7:9] == bytes([0xFF, 0x0F])  # x = 4095 LE
        assert data[9:11] == bytes([0x00, 0x08])  # y = 2048 LE
        assert data[11] == 0xFF  # wheel = -1 (two's complement)
        assert sum(data[:-1]) & 0xFF == data[-1]

    def test_mouse_packet_clamps_out_of_range(self):
        data = mouse_abs_packet(99999, -5)
        assert data[7:9] == bytes([0xFF, 0x0F])
        assert data[9:11] == bytes([0x00, 0x00])

    def test_char_to_hid(self):
        assert _char_to_hid("a") == (0x00, 0x04)
        assert _char_to_hid("A") == (0x02, 0x04)  # shift + a
        assert _char_to_hid("1") == (0x00, 0x1E)
        assert _char_to_hid("!") == (0x02, 0x1E)  # shift + 1
        assert _char_to_hid(" ") == (0x00, 0x2C)
        with pytest.raises(ValueError):
            _char_to_hid("€")


# --------------------------------------------------------------------------
# executor via NullSerialTransport — no serial port is ever opened
# --------------------------------------------------------------------------
@pytest.fixture
def hid():
    transport = NullSerialTransport()
    ex = CH9329Executor(transport=transport, screen_width=1920, screen_height=1080, press_delay=0.0)
    return ex, transport


class TestCH9329Executor:
    def test_click_is_press_then_release(self, hid):
        ex, t = hid
        out = ex.execute(Action(ActionKind.CLICK, 1, x=100, y=50))
        assert "clicked" in out
        (cmd0, d0), (cmd1, d1) = t.parsed()
        assert cmd0 == cmd1 == 0x04  # two abs-mouse frames
        assert d0[1] == 0x01 and d1[1] == 0x00  # press, then release
        assert d0[2:6] == d1[2:6]  # same coordinates both times

    def test_right_and_double_click(self, hid):
        ex, t = hid
        ex.execute(Action(ActionKind.RIGHT_CLICK, 1, x=1, y=1))
        ex.execute(Action(ActionKind.DOUBLE_CLICK, 1, x=1, y=1))
        parsed = t.parsed()
        assert len(parsed) == 2 + 4  # right (press+rel) + double (2x press+rel)
        assert parsed[0][1][1] == 0x02  # right button bit
        assert all(d[1] == 0x01 for _, d in parsed[2::2])  # all presses left

    def test_type_produces_per_char_press_release(self, hid):
        ex, t = hid
        out = ex.execute(Action(ActionKind.TYPE, 1, text="aA!"))
        assert out == "typed 3 chars"
        parsed = t.parsed()
        assert len(parsed) == 6
        presses = [d for i, (cmd, d) in enumerate(parsed) if i % 2 == 0]
        releases = [d for i, (cmd, d) in enumerate(parsed) if i % 2 == 1]
        assert all(cmd == 0x02 for cmd, _ in parsed)
        assert [(d[0], d[2]) for d in presses] == [(0x00, 0x04), (0x02, 0x04), (0x02, 0x1E)]
        assert all(d == bytes(8) for d in releases)

    def test_key_chord(self, hid):
        ex, t = hid
        ex.execute(Action(ActionKind.KEY, 1, keys=("ctrl", "s")))
        (cmd0, d0), (cmd1, d1) = t.parsed()
        assert d0[0] == 0x01  # ctrl modifier
        assert d0[2] == 0x16  # 's' keycode
        assert d1 == bytes(8)  # all keys released

    def test_scroll_wheel_byte(self, hid):
        ex, t = hid
        ex.execute(Action(ActionKind.SCROLL, 1, x=500, y=400, amount=-3))
        ((cmd, d),) = t.parsed()
        assert cmd == 0x04 and d[6] == (-3 & 0xFF)

    def test_drag_holds_button_while_moving(self, hid):
        ex, t = hid
        ex.execute(Action(ActionKind.DRAG, 1, x=10, y=20, to_x=300, to_y=400))
        parsed = t.parsed()
        assert [d[1] for _, d in parsed] == [0x01, 0x01, 0x00]  # grab, move held, drop
        # start coords scaled into 4095 space
        sx, sy = _to_abs_coords(10, 20, 1920, 1080)
        assert parsed[0][1][2] | parsed[0][1][3] << 8 == sx
        assert parsed[0][1][4] | parsed[0][1][5] << 8 == sy

    def test_wait_sends_nothing(self, hid):
        ex, t = hid
        assert "waited" in ex.execute(Action(ActionKind.WAIT, 1, seconds=0.01))
        assert t.frames == []

    def test_executor_through_gatekeeper_is_executed_and_audited(self, hid, tmp_path):
        ex, t = hid
        cfg = load_config(audit_log_path=tmp_path / "a.jsonl", risk_policy_path=tmp_path / "p.json")
        fresh = FreshnessTracker()
        fresh.observe(1)
        gate = Gatekeeper(cfg, fresh, approval_backend=AutoApprove(), executor=ex)
        f = Frame.from_image(1, Image.new("RGB", (64, 64), (1, 2, 3)))
        d = gate.request_action(Action(ActionKind.CLICK, 1, x=5, y=5), f)
        assert d.kind is DecisionKind.EXECUTED  # name != dry-run => real execution
        assert len(t.frames) == 2  # press + release hit the wire

    def test_import_guard_without_pyserial(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "serial", None)  # simulate missing pyserial
        with pytest.raises(RuntimeError, match="pyserial"):
            CH9329Executor(port="/dev/ttyUSB9")
        # ...while a NullSerialTransport never needs pyserial at all
        CH9329Executor(transport=NullSerialTransport(), press_delay=0.0)


# --------------------------------------------------------------------------
# UVCCapture with a stubbed cv2 — no capture card is ever opened
# --------------------------------------------------------------------------
class _FakeVideoCapture:
    def __init__(self, index):
        self.index = index
        self.props = {}
        self.released = False
        self._bgr = np.zeros((4, 6, 3), dtype=np.uint8)
        self._bgr[:, :] = (10, 20, 30)  # B, G, R

    def isOpened(self):
        return True

    def set(self, prop, value):
        self.props[prop] = value
        return True

    def get(self, prop):
        return self.props.get(prop, 0.0)

    def read(self):
        return True, self._bgr.copy()

    def release(self):
        self.released = True


class _FakeCv2:
    CAP_PROP_FOURCC = 6
    CAP_PROP_FRAME_WIDTH = 3
    CAP_PROP_FRAME_HEIGHT = 4
    COLOR_BGR2RGB = 104

    def __init__(self):
        self.last_device = None

    def VideoCapture(self, index):
        self.last_device = _FakeVideoCapture(index)
        return self.last_device

    def VideoWriter_fourcc(self, *chars):
        return "".join(chars)

    def cvtColor(self, arr, code):
        assert code == self.COLOR_BGR2RGB
        return arr[:, :, ::-1].copy()  # BGR -> RGB


@pytest.fixture
def fake_cv2(monkeypatch):
    fake = _FakeCv2()
    monkeypatch.setitem(sys.modules, "cv2", fake)
    return fake


class TestUVCCapture:
    def test_satisfies_protocol_and_frame_ids(self, fake_cv2):
        cap = UVCCapture(device_index=1, width=1920, height=1080)
        assert isinstance(cap, ScreenCapture)
        f1, f2 = cap.grab(), cap.grab()
        assert (f1.frame_id, f2.frame_id) == (1, 2)  # MSSCapture semantics
        assert f1.image.mode == "RGB"
        assert f1.sha256 != f2.sha256 or f1.image.tobytes() == f2.image.tobytes()
        cap.close()
        assert fake_cv2.last_device.released

    def test_bgr_is_converted_to_rgb(self, fake_cv2):
        cap = UVCCapture()
        px = cap.grab().image.getpixel((0, 0))
        assert px == (30, 20, 10)  # BGR (10,20,30) -> RGB (30,20,10)

    def test_requests_mjpg_and_resolution(self, fake_cv2):
        UVCCapture(device_index=0, width=1280, height=720)
        props = fake_cv2.last_device.props
        assert props[_FakeCv2.CAP_PROP_FOURCC] == "MJPG"
        assert props[_FakeCv2.CAP_PROP_FRAME_WIDTH] == 1280
        assert props[_FakeCv2.CAP_PROP_FRAME_HEIGHT] == 720

    def test_import_guard_without_cv2(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "cv2", None)  # simulate missing opencv
        with pytest.raises(RuntimeError, match="opencv-python"):
            UVCCapture()

    def test_read_failure_raises_clear_error(self, fake_cv2):
        cap = UVCCapture()
        fake_cv2.last_device.read = lambda: (False, None)
        with pytest.raises(RuntimeError, match="no frame"):
            cap.grab()


# --------------------------------------------------------------------------
# config + crash-cart assembly
# --------------------------------------------------------------------------
class TestConfigAndAssembly:
    def test_defaults_are_topology_a_safe(self):
        cfg = load_config()
        assert cfg.capture_backend == "mss"
        assert cfg.executor_backend == "dryrun"
        assert cfg.ch9329_baudrate == 9600  # chip factory default
        assert cfg.ch9329_port == "/dev/ttyUSB0"
        assert cfg.uvc_device_index == 0

    def test_topology_b_config_parses(self):
        cfg = load_config(
            capture_backend="uvc",
            executor_backend="ch9329",
            uvc_device_index=2,
            ch9329_port="COM3",
            ch9329_baudrate=115200,
        )
        assert cfg.capture_backend == "uvc"
        assert cfg.executor_backend == "ch9329"
        assert cfg.uvc_device_index == 2
        assert cfg.ch9329_port == "COM3"
        assert cfg.ch9329_baudrate == 115200

    def test_assembly_selects_uvc_capture(self, fake_cv2):
        cfg = load_config(capture_backend="uvc", uvc_device_index=3)
        cap = run_crashcart.build_capture(cfg)
        assert isinstance(cap, UVCCapture)
        assert fake_cv2.last_device.index == 3
        cap.close()

    def test_assembly_selects_ch9329_executor(self, monkeypatch):
        opened = {}

        def fake_open(port, baudrate):
            opened.update(port=port, baudrate=baudrate)
            return NullSerialTransport()

        monkeypatch.setattr("psoperator.gatekeeper.executor_ch9329._open_serial", fake_open)
        cfg = load_config(
            executor_backend="ch9329", ch9329_port="/dev/ttyUSB7", ch9329_baudrate=9600
        )
        ex = run_crashcart.build_executor(cfg)
        assert isinstance(ex, CH9329Executor) and ex.name == "ch9329"
        assert opened == {"port": "/dev/ttyUSB7", "baudrate": 9600}

    def test_assembly_defaults(self):
        assert isinstance(run_crashcart.build_executor(load_config()), DryRunExecutor)
        with pytest.raises(ValueError, match="unknown executor_backend"):
            run_crashcart.build_executor(load_config(executor_backend="telepathy"))
        with pytest.raises(ValueError, match="unknown capture_backend"):
            run_crashcart.build_capture(load_config(capture_backend="eyeballs"))
