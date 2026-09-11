"""R-205 — deployment isolation invariants.

The exit criterion is: the planner account cannot reach the observer's signing
material. The mechanisms live in :mod:`psoperator.common.attestation` (owner-only
mode, owner-uid, TOCTOU-safe key files) and :mod:`psoperator.common.ipc`
(loopback-only bind). These tests assert them together as the deployment boundary
the two-account topology (governance vs. planner) rests on — see
``docs/deployment-isolation.md``.
"""

from __future__ import annotations

import os
import stat

import pytest

from psoperator.common.attestation import (
    AttestationKeyError,
    load_attestation_key,
    provision_attestation_key,
)
from psoperator.common.ipc import IPCServer

# --- the IPC surface is loopback-only ---------------------------------------


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "example.com", "::", "192.168.1.10"])
def test_ipc_refuses_any_non_loopback_bind(host):
    # A planner reaches the gatekeeper only over loopback; the service refuses to
    # expose itself on a routable interface at all.
    with pytest.raises(ValueError, match="loopback"):
        IPCServer(host, 8765)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_ipc_binds_only_loopback(host):
    IPCServer(host, 8765)  # constructs without raising


# --- the observer's signing material is owner-only --------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key files (Windows ACL is separate)")
def test_a_provisioned_key_is_owner_only(tmp_path):
    key = tmp_path / "observer-key.json"
    provision_attestation_key(key, "observer-v1")
    # No group or other permission bits — only the owning (governance) account
    # can read it; the OS denies every other account, including the planner.
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key files")
def test_a_key_reachable_beyond_its_owner_is_refused_fail_closed(tmp_path):
    # The R-205 property, fail-closed: if the key were ever broadened to a shape a
    # separate planner account could read (group- or world-readable), loading it
    # is refused rather than trusted. A misconfiguration cannot silently expose it.
    key = tmp_path / "observer-key.json"
    provision_attestation_key(key, "observer-v1")
    for mode in (0o640, 0o644, 0o604, 0o660):
        key.chmod(mode)
        with pytest.raises(AttestationKeyError, match="group/other"):
            load_attestation_key(key)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only key directories")
def test_the_key_directory_must_be_owner_only(tmp_path):
    # Provisioning refuses a directory any other account could write into — a
    # world-writable dir would let another account plant or swap the key.
    permissive = tmp_path / "shared"
    permissive.mkdir(mode=0o755)
    permissive.chmod(0o755)
    with pytest.raises(AttestationKeyError, match="group/other"):
        provision_attestation_key(permissive / "key.json", "observer-v1")
