"""Independent observer service, protocol bounds, and failure lifecycle."""

from __future__ import annotations

import json
import socket

import pytest
from PIL import Image
from pydantic import ValidationError

import psoperator.services.observer as observer_module
import psoperator.services.observer_client as observer_client_module
from psoperator.common.attestation import AttestationKey, SnapshotSigner
from psoperator.common.ipc import MAX_MESSAGE_BYTES, recv_json, send_json
from psoperator.common.schema import (
    MAX_CONTROL_TYPE_CHARS,
    MAX_ELEMENT_LABEL_CHARS,
    MAX_SNAPSHOT_ELEMENTS,
    OBSERVER_PROTOCOL_VERSION,
    AttestedSnapshot,
    ObserverHealth,
    PerceptionSnapshot,
    UIElementRef,
)
from psoperator.config import load_config
from psoperator.perception.a11y import A11yNode, WinAutoA11y
from psoperator.perception.capture import Frame
from psoperator.perception.ocr import RapidOCRProvider, TextBox
from psoperator.perception.snapshot import SnapshotBuilder
from psoperator.services.observer import ObserverService
from psoperator.services.observer_client import ObserverClient, ObserverUnavailable


class SequenceCapture:
    dirty_region_hook = None

    def __init__(self, results):
        self.results = list(results)
        self.closed = False

    def grab(self):
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def close(self):
        self.closed = True


class EmptyA11y:
    def tree(self, max_nodes=None):
        return None

    def find(self, role=None, name=None):
        return None


class EmptyOCR:
    def extract(self, image, max_results=None):
        return []

    def find(self, image, needle):
        return None


def _frame(frame_id: int, captured_at: float, color: str = "white") -> Frame:
    return Frame.from_image(frame_id, Image.new("RGB", (80, 60), color), captured_at=captured_at)


def _service(capture, clock_values=(100.0, 101.0, 102.0, 103.0, 104.0)) -> ObserverService:
    values = iter(clock_values)
    nonces = iter(range(1, 100))
    signer = SnapshotSigner(
        AttestationKey("test-observer", b"k" * 32),
        observer_epoch="e" * 64,
        nonce_factory=lambda: f"{next(nonces):064x}",
    )
    return ObserverService(
        capture,
        signer,
        SnapshotBuilder(EmptyA11y(), EmptyOCR()),
        clock=lambda: next(values),
    )


def test_observer_assigns_own_monotonic_sequence_and_frame_metadata():
    capture = SequenceCapture([_frame(90, 10.5), _frame(3, 11.5, "black")])
    service = _service(capture)

    first = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    second = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    one_envelope = AttestedSnapshot.model_validate(first["attestation"])
    two_envelope = AttestedSnapshot.model_validate(second["attestation"])
    one = one_envelope.snapshot
    two = two_envelope.snapshot

    assert (one.frame_id, two.frame_id) == (1, 2)
    assert (one.captured_at, two.captured_at) == (101.0, 103.0)
    assert one.screen_size == two.screen_size == (80, 60)
    assert one.frame_hash != two.frame_hash
    assert one_envelope.body.nonce != two_envelope.body.nonce
    assert one_envelope.body.observer_epoch == two_envelope.body.observer_epoch == "e" * 64
    assert second["health"]["last_sequence"] == 2


def test_observer_response_is_bounded_json_without_image_objects():
    service = _service(SequenceCapture([_frame(1, 10.0)]))
    response = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    encoded = json.dumps(response).encode("utf-8")

    assert len(encoded) < MAX_MESSAGE_BYTES
    assert "image" not in response["attestation"]["body"]["snapshot"]
    assert "snapshot" not in response
    assert response["protocol_version"] == OBSERVER_PROTOCOL_VERSION

    left, right = socket.socketpair()
    try:
        send_json(left, response)
        assert recv_json(right) == response
    finally:
        left.close()
        right.close()


def test_failure_degrades_without_consuming_sequence_then_recovers():
    capture = SequenceCapture([RuntimeError("camera disconnected"), _frame(77, 12.0)])
    service = _service(capture)

    failed = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    assert not failed["ok"]
    assert failed["health"]["status"] == "degraded"
    assert failed["health"]["last_sequence"] == 0
    assert failed["health"]["consecutive_failures"] == 1
    assert "camera disconnected" in failed["error"]

    recovered = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    assert recovered["ok"]
    assert recovered["attestation"]["body"]["snapshot"]["frame_id"] == 1
    assert recovered["health"]["status"] == "ready"
    assert recovered["health"]["consecutive_failures"] == 0
    assert recovered["health"]["error"] == ""


def test_failure_error_prefix_and_detail_share_one_bound():
    service = _service(SequenceCapture([RuntimeError("x" * 1_000)]))
    failed = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    assert len(failed["error"]) == 512
    assert failed["error"] == f"observer unavailable: {failed['health']['error']}"


def test_mismatched_perception_metadata_fails_closed():
    class MismatchedBuilder:
        def build(self, frame):
            return PerceptionSnapshot(
                frame_id=frame.frame_id,
                captured_at=frame.captured_at,
                frame_hash="f" * 64,
                screen_size=frame.image.size,
            )

    capture = SequenceCapture([_frame(1, 10.0)])
    signer = SnapshotSigner(AttestationKey("test-observer", b"k" * 32))
    service = ObserverService(capture, signer, MismatchedBuilder(), clock=lambda: 100.0)
    response = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    assert not response["ok"]
    assert response["health"]["last_sequence"] == 0
    assert "does not match" in response["error"]


def test_health_is_available_without_capture_and_close_is_idempotent():
    capture = SequenceCapture([])
    service = _service(capture, clock_values=(100.0,))

    health = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "health"})
    assert health["ok"] and health["health"]["status"] == "ready"
    assert health["health"]["last_success_at"] is None

    service.close()
    service.close()
    assert capture.closed
    stopped = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "health"})
    assert stopped["health"]["status"] == "stopped"
    unavailable = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    assert not unavailable["ok"] and "stopped" in unavailable["error"]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"op": "health"},
        {"version": OBSERVER_PROTOCOL_VERSION, "op": "capture"},
        {"version": 1, "op": "health"},
        {"version": OBSERVER_PROTOCOL_VERSION, "op": "health", "pickle": "forbidden"},
    ],
)
def test_protocol_rejects_missing_unknown_and_extra_fields(payload):
    service = _service(SequenceCapture([]), clock_values=(100.0,))
    response = service.handle(payload)
    assert not response["ok"]
    assert response["error"].startswith("invalid observer request:")
    assert len(response["error"]) <= 512


class LargeA11y:
    def tree(self, max_nodes=None):
        long_label = "L" * (MAX_ELEMENT_LABEL_CHARS + 100)
        long_role = "R" * (MAX_CONTROL_TYPE_CHARS + 100)
        return A11yNode(
            long_role,
            long_label,
            (0, 0, 10, 10),
            children=tuple(
                A11yNode("button", f"button-{index}", (index, 1, 1, 1)) for index in range(20)
            ),
        )

    def find(self, role=None, name=None):
        return None


class LargeOCR:
    def extract(self, image, max_results=None):
        boxes = [TextBox(f"ocr-{index}", (index, 2, 1, 1), 0.9) for index in range(20)]
        return boxes[:max_results]

    def find(self, image, needle):
        return None


def test_snapshot_builder_bounds_inventory_and_text_fields():
    snapshot = SnapshotBuilder(LargeA11y(), LargeOCR(), max_elements=3).build(_frame(1, 10.0))
    assert len(snapshot.elements) == 3
    assert len(snapshot.elements[0].label) == MAX_ELEMENT_LABEL_CHARS
    assert len(snapshot.elements[0].control_type) == MAX_CONTROL_TYPE_CHARS
    assert all(item.source == "a11y" for item in snapshot.elements)


def test_element_ids_bind_to_exact_frame_hash_not_only_sequence():
    builder = SnapshotBuilder(LargeA11y(), EmptyOCR(), max_elements=1)
    white = builder.build(_frame(1, 10.0, "white"))
    black = builder.build(_frame(1, 10.0, "black"))
    assert white.frame_id == black.frame_id == 1
    assert white.frame_hash != black.frame_hash
    assert white.elements[0].element_id != black.elements[0].element_id


def test_snapshot_builder_caps_examined_items_for_noncooperating_providers():
    examined = 0

    class Node:
        name = "invisible"
        role = "button"
        children = ()

        @property
        def bounds(self):
            nonlocal examined
            examined += 1
            return None

    class UnboundedA11y:
        def tree(self):
            root = Node()
            root.children = tuple(Node() for _ in range(20))
            return root

        def find(self, role=None, name=None):
            return None

    class UnboundedOCR:
        def extract(self, image):
            for index in range(20):
                if index >= 3:
                    raise AssertionError("OCR work limit was not enforced")
                yield TextBox("duplicate", (0, 0, 1, 1), 0.9)

        def find(self, image, needle):
            return None

    snapshot = SnapshotBuilder(UnboundedA11y(), UnboundedOCR(), max_elements=3).build(
        _frame(1, 10.0)
    )
    assert examined == 3
    assert len(snapshot.elements) == 1


def test_snapshot_builder_supports_legacy_provider_signatures():
    class LegacyA11y:
        def tree(self):
            return None

        def find(self, role=None, name=None):
            return None

    class LegacyOCR:
        def extract(self, image):
            return []

        def find(self, image, needle):
            return None

    snapshot = SnapshotBuilder(LegacyA11y(), LegacyOCR(), max_elements=1).build(_frame(1, 10.0))
    assert snapshot.elements == ()


def test_windows_a11y_conversion_respects_work_limit():
    class Wrapper:
        def __init__(self, name, children=()):
            self.name = name
            self._children = children

        def rectangle(self):
            raise RuntimeError("no bounds")

        def friendly_class_name(self):
            return "button"

        def window_text(self):
            return self.name

        def children(self):
            return self._children

    root = Wrapper("one", (Wrapper("two", (Wrapper("three", (Wrapper("four"),)),)),))
    provider = object.__new__(WinAutoA11y)
    provider._desktop = type("Desktop", (), {"windows": lambda self: [root]})()
    tree = provider.tree(max_nodes=3)
    assert tree is not None
    assert [node.name for node in tree.walk()] == ["root", "one", "two", "three"]


def test_rapid_ocr_adaptation_respects_result_limit():
    points = [(0, 0), (1, 0), (1, 1), (0, 1)]
    provider = object.__new__(RapidOCRProvider)
    provider._ocr = lambda image: ([(points, str(index), 0.9) for index in range(10)], None)
    assert len(provider.extract(Image.new("RGB", (2, 2)), max_results=2)) == 2


def test_rapid_ocr_adaptation_handles_v2_output_object():
    points = [(0, 0), (4, 0), (4, 2), (0, 2)]
    output = type(
        "RapidOCROutput",
        (),
        {
            "boxes": [points] * 10,
            "txts": tuple(str(index) for index in range(10)),
            "scores": (0.9,) * 10,
        },
    )()
    provider = object.__new__(RapidOCRProvider)
    provider._ocr = lambda image: output
    boxes = provider.extract(Image.new("RGB", (8, 8)), max_results=2)
    assert len(boxes) == 2
    assert boxes[0].text == "0"
    assert boxes[0].box == (0, 0, 4, 2)
    assert boxes[0].confidence == 0.9


def test_rapid_ocr_adaptation_handles_v2_empty_output():
    output = type("RapidOCROutput", (), {"boxes": None, "txts": None, "scores": None})()
    provider = object.__new__(RapidOCRProvider)
    provider._ocr = lambda image: output
    assert provider.extract(Image.new("RGB", (8, 8))) == []


def test_snapshot_schema_rejects_inventory_over_global_limit():
    element = UIElementRef(
        element_id="item",
        frame_id=1,
        bbox=(0, 0, 1, 1),
        source="a11y",
    )
    with pytest.raises(ValidationError, match="512"):
        PerceptionSnapshot(
            frame_id=1,
            captured_at=10.0,
            frame_hash="a" * 64,
            screen_size=(80, 60),
            elements=tuple(element.model_copy(update={"element_id": str(i)}) for i in range(513)),
        )


def test_client_validates_success_health_and_service_failure(monkeypatch):
    capture = SequenceCapture([_frame(1, 10.0), RuntimeError("device lost")])
    service = _service(capture)
    monkeypatch.setattr(
        observer_client_module,
        "ipc_request",
        lambda host, port, payload, timeout: service.handle(payload),
    )
    client = ObserverClient("127.0.0.1", 8764)

    attestation = client.observe()
    assert attestation.snapshot.frame_id == 1
    health = client.health()
    assert isinstance(health, ObserverHealth) and health.status == "ready"
    with pytest.raises(ObserverUnavailable, match="device lost") as raised:
        client.observe()
    assert raised.value.health is not None
    assert raised.value.health.status == "degraded"
    assert str(raised.value) == "observer unavailable: RuntimeError: device lost"


def test_client_fails_closed_on_transport_and_malformed_responses(monkeypatch):
    client = ObserverClient("127.0.0.1", 8764)

    def disconnected(*args, **kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(observer_client_module, "ipc_request", disconnected)
    with pytest.raises(ObserverUnavailable, match="refused") as raised:
        client.observe()
    assert str(raised.value) == "observer unavailable: refused"

    monkeypatch.setattr(
        observer_client_module,
        "ipc_request",
        lambda *args, **kwargs: {"ok": True, "protocol_version": 99},
    )
    with pytest.raises(ObserverUnavailable, match="protocol version"):
        client.health()

    monkeypatch.setattr(
        observer_client_module,
        "ipc_request",
        lambda *args, **kwargs: {"ok": False, "error": "RuntimeError: handler failed"},
    )
    with pytest.raises(ObserverUnavailable, match="observer service error: RuntimeError"):
        client.health()

    monkeypatch.setattr(
        observer_client_module,
        "ipc_request",
        lambda *args, **kwargs: {
            "ok": True,
            "protocol_version": OBSERVER_PROTOCOL_VERSION,
            "attestation": {"body": {}, "signature": "bad"},
            "health": ObserverHealth(
                status="ready",
                backend="test",
                started_at=1.0,
                attestation_key_id="test-observer",
                observer_epoch="e" * 64,
            ).model_dump(mode="json"),
        },
    )
    with pytest.raises(ObserverUnavailable, match="invalid attestation"):
        client.observe()

    monkeypatch.setattr(
        observer_client_module,
        "ipc_request",
        lambda *args, **kwargs: {
            "ok": True,
            "protocol_version": OBSERVER_PROTOCOL_VERSION,
            "attestation": {},
        },
    )
    with pytest.raises(ObserverUnavailable, match="invalid health"):
        client.observe()

    service = _service(SequenceCapture([_frame(1, 10.0)]))
    mismatched = service.handle({"version": OBSERVER_PROTOCOL_VERSION, "op": "observe"})
    mismatched["health"]["attestation_key_id"] = "different-key"
    monkeypatch.setattr(observer_client_module, "ipc_request", lambda *args, **kwargs: mismatched)
    with pytest.raises(ObserverUnavailable, match="does not match service health"):
        client.observe()


def test_max_elements_configuration_range_is_enforced():
    with pytest.raises(ValueError, match="between"):
        SnapshotBuilder(EmptyA11y(), EmptyOCR(), max_elements=0)
    with pytest.raises(ValueError, match="between"):
        SnapshotBuilder(EmptyA11y(), EmptyOCR(), max_elements=MAX_SNAPSHOT_ELEMENTS + 1)


def test_observer_configuration_defaults_and_bounds():
    config = load_config()
    assert config.observer_host == "127.0.0.1"
    assert config.observer_port == 8764
    assert config.observer_timeout_s == 5.0
    assert config.observer_max_elements == MAX_SNAPSHOT_ELEMENTS
    assert config.observer_attestation_key_path is None
    assert config.observer_snapshot_ttl_s == 10.0
    with pytest.raises(ValidationError):
        load_config(observer_max_elements=MAX_SNAPSHOT_ELEMENTS + 1)
    with pytest.raises(ValidationError):
        load_config(observer_snapshot_ttl_s=61.0)


def test_serve_always_closes_capture_when_ipc_loop_exits(monkeypatch):
    class BrokenServer:
        def __init__(self, host, port):
            assert (host, port) == ("127.0.0.1", 8764)

        def serve_forever(self, handler):
            raise RuntimeError("server stopped")

    capture = SequenceCapture([])
    signer = SnapshotSigner(AttestationKey("test-observer", b"k" * 32))
    monkeypatch.setattr(observer_module, "IPCServer", BrokenServer)
    with pytest.raises(RuntimeError, match="server stopped"):
        observer_module.serve("127.0.0.1", 8764, capture, signer)
    assert capture.closed


def test_capture_factory_rejects_unknown_backend():
    with pytest.raises(ValueError, match="unknown capture backend"):
        observer_module.build_capture(load_config(), backend="telepathy")
