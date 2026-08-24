"""R-202 snapshot envelope, key provisioning, and rotation invariants."""

from __future__ import annotations

import json
import os
import stat

import pytest
from pydantic import ValidationError

from psoperator.cli import _run_observer, main
from psoperator.common.attestation import (
    AttestationKey,
    AttestationKeyError,
    AttestationKeyring,
    SnapshotSigner,
    UnknownAttestationKey,
    attestation_signature_matches,
    load_attestation_key,
    provision_attestation_key,
)
from psoperator.common.schema import (
    MAX_SNAPSHOT_TTL_SECONDS,
    AttestedSnapshot,
    PerceptionSnapshot,
    SnapshotAttestationBody,
    UIElementRef,
)
from psoperator.config import load_config


def _snapshot(*, frame_id: int = 7, captured_at: float = 100.0) -> PerceptionSnapshot:
    return PerceptionSnapshot(
        frame_id=frame_id,
        captured_at=captured_at,
        frame_hash="a" * 64,
        screen_size=(80, 60),
        elements=(
            UIElementRef(
                element_id="a11y-" + "b" * 24,
                frame_id=frame_id,
                label="Save",
                bbox=(1, 2, 10, 8),
                control_type="button",
                source="a11y",
            ),
        ),
    )


def _key(key_id: str = "observer-2026-08") -> AttestationKey:
    return AttestationKey(key_id, b"s" * 32, created_at=90.0)


def test_signer_covers_complete_snapshot_and_required_metadata():
    signer = SnapshotSigner(
        _key(),
        ttl_s=10.0,
        observer_epoch="e" * 64,
        nonce_factory=lambda: "c" * 64,
    )
    envelope = signer.sign(_snapshot(), issued_at=101.0)

    assert envelope.body.signature_version == 1
    assert envelope.body.key_id == "observer-2026-08"
    assert envelope.body.observer_epoch == "e" * 64
    assert envelope.body.issued_at == 101.0
    assert envelope.body.expires_at == 111.0
    assert envelope.body.nonce == "c" * 64
    assert envelope.snapshot == _snapshot()
    assert len(envelope.signature) == 64
    assert attestation_signature_matches(_key(), envelope)


@pytest.mark.parametrize("field,value", [("nonce", "d" * 64), ("expires_at", 112.0)])
def test_signature_detects_attestation_metadata_mutation(field, value):
    key = _key()
    envelope = SnapshotSigner(
        key,
        observer_epoch="e" * 64,
        nonce_factory=lambda: "c" * 64,
    ).sign(_snapshot(), issued_at=101.0)
    tampered_body = envelope.body.model_copy(update={field: value})
    tampered = envelope.model_copy(update={"body": tampered_body})
    assert not attestation_signature_matches(key, tampered)


def test_signature_detects_any_snapshot_field_mutation():
    key = _key()
    envelope = SnapshotSigner(key, observer_epoch="e" * 64).sign(_snapshot(), issued_at=101.0)
    changed_snapshot = envelope.snapshot.model_copy(update={"frame_hash": "f" * 64})
    changed_body = envelope.body.model_copy(update={"snapshot": changed_snapshot})
    tampered = envelope.model_copy(update={"body": changed_body})
    assert not attestation_signature_matches(key, tampered)


def test_attestation_schema_rejects_invalid_lifetimes_and_identifiers():
    base = {
        "signature_version": 1,
        "key_id": "observer-2026-08",
        "observer_epoch": "e" * 64,
        "issued_at": 101.0,
        "expires_at": 111.0,
        "nonce": "c" * 64,
        "snapshot": _snapshot(),
    }
    with pytest.raises(ValidationError, match="cannot predate"):
        SnapshotAttestationBody(**{**base, "issued_at": 99.0})
    with pytest.raises(ValidationError, match="lifetime"):
        SnapshotAttestationBody(**{**base, "expires_at": 101.0 + MAX_SNAPSHOT_TTL_SECONDS + 0.1})
    with pytest.raises(ValidationError):
        SnapshotAttestationBody(**{**base, "key_id": "../../secret"})
    with pytest.raises(ValidationError):
        SnapshotAttestationBody(**{**base, "nonce": "short"})
    with pytest.raises(ValidationError):
        SnapshotAttestationBody(**{**base, "observer_epoch": "G" * 64})
    without_version = {key: value for key, value in base.items() if key != "signature_version"}
    with pytest.raises(ValidationError):
        SnapshotAttestationBody(**without_version)
    with pytest.raises(ValidationError):
        SnapshotAttestationBody(**{**base, "signature_version": 2})


def test_snapshot_schema_rejects_duplicate_and_cross_frame_element_ids():
    snapshot = _snapshot()
    element = snapshot.elements[0]
    with pytest.raises(ValidationError, match="unique"):
        PerceptionSnapshot(
            **snapshot.model_dump(exclude={"elements"}),
            elements=(element, element),
        )
    with pytest.raises(ValidationError, match="snapshot frame"):
        PerceptionSnapshot(
            **snapshot.model_dump(exclude={"elements"}),
            elements=(element.model_copy(update={"frame_id": snapshot.frame_id + 1}),),
        )


def test_attested_snapshot_is_strict_and_signature_is_canonical():
    envelope = SnapshotSigner(_key(), observer_epoch="e" * 64).sign(_snapshot(), issued_at=101.0)
    decoded = AttestedSnapshot.model_validate_json(envelope.model_dump_json())
    assert decoded == envelope
    with pytest.raises(ValidationError):
        AttestedSnapshot.model_validate({**envelope.model_dump(), "unsigned": True})
    wrong_key = AttestationKey("other-key", b"s" * 32)
    assert not attestation_signature_matches(wrong_key, envelope)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key files")
def test_provision_load_and_refuse_overwrite(tmp_path):
    path = tmp_path / "observer-key.json"
    created = provision_attestation_key(path, "observer-v1", clock=lambda: 123.0)
    loaded = load_attestation_key(path)

    assert loaded == created
    assert "secret" not in repr(loaded)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(AttestationKeyError, match="refusing to overwrite"):
        provision_attestation_key(path, "observer-v2")


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key files")
def test_provision_requires_precreated_owner_only_directory(tmp_path):
    with pytest.raises(AttestationKeyError, match="pre-provisioned owner-only"):
        provision_attestation_key(tmp_path / "missing" / "key.json", "observer-v1")

    permissive = tmp_path / "permissive"
    permissive.mkdir(mode=0o755)
    permissive.chmod(0o755)
    with pytest.raises(AttestationKeyError, match="group/other"):
        provision_attestation_key(permissive / "key.json", "observer-v1")

    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(AttestationKeyError, match="real directory"):
        provision_attestation_key(linked / "key.json", "observer-v1")


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode semantics")
def test_key_loader_rejects_group_permissions_and_symlinks(tmp_path):
    path = tmp_path / "observer-key.json"
    provision_attestation_key(path, "observer-v1")
    path.chmod(0o640)
    with pytest.raises(AttestationKeyError, match="group/other"):
        load_attestation_key(path)

    path.chmod(0o600)
    link = tmp_path / "linked-key.json"
    link.symlink_to(path)
    with pytest.raises(AttestationKeyError, match="symlink"):
        load_attestation_key(link)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key files")
def test_key_loader_rejects_malformed_and_oversized_files(tmp_path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps({"format_version": 1, "key_id": "key"}))
    malformed.chmod(0o600)
    with pytest.raises(AttestationKeyError, match="invalid"):
        load_attestation_key(malformed)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 4097)
    oversized.chmod(0o600)
    with pytest.raises(AttestationKeyError, match="size limit"):
        load_attestation_key(oversized)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key files")
def test_rotation_requires_explicit_keyring_membership(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old = provision_attestation_key(old_path, "observer-old")
    new = provision_attestation_key(new_path, "observer-new")

    overlap = AttestationKeyring.from_paths((old_path, new_path))
    assert overlap.require(old.key_id) == old
    assert overlap.require(new.key_id) == new

    retired = AttestationKeyring.from_paths((new_path,))
    with pytest.raises(UnknownAttestationKey, match="unknown or retired"):
        retired.require(old.key_id)
    with pytest.raises(AttestationKeyError, match="duplicate"):
        AttestationKeyring((old, old))


def test_signer_rejects_invalid_ttl_epoch_nonce_and_predated_issue_time():
    with pytest.raises(ValueError, match="ttl_s"):
        SnapshotSigner(_key(), ttl_s=0)
    with pytest.raises(ValueError, match="observer_epoch"):
        SnapshotSigner(_key(), observer_epoch="short")
    with pytest.raises(ValidationError):
        SnapshotSigner(_key(), nonce_factory=lambda: "bad").sign(_snapshot(), issued_at=101.0)
    with pytest.raises(ValidationError, match="cannot predate"):
        SnapshotSigner(_key()).sign(_snapshot(), issued_at=99.0)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key files")
def test_cli_provisions_key_explicitly_and_never_overwrites(tmp_path, capsys):
    path = tmp_path / "observer.json"
    assert main(["attestation-keygen", "--path", str(path), "--key-id", "observer-v1"]) == 0
    assert load_attestation_key(path).key_id == "observer-v1"
    assert "provisioned attestation key 'observer-v1'" in capsys.readouterr().out

    assert main(["attestation-keygen", "--path", str(path), "--key-id", "observer-v2"]) == 2
    assert load_attestation_key(path).key_id == "observer-v1"
    assert "refusing to overwrite" in capsys.readouterr().out


def test_observer_startup_requires_explicit_key_path_before_capture(capsys):
    assert _run_observer(load_config(observer_attestation_key_path=None), backend="mss") == 2
    assert "OBSERVER_ATTESTATION_KEY_PATH is required" in capsys.readouterr().out
