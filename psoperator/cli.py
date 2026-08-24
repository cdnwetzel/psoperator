"""Command-line entry point for operational and service commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from psoperator.common.attestation import (
    AttestationKeyError,
    SnapshotSigner,
    load_attestation_key,
    provision_attestation_key,
)
from psoperator.common.auth import load_or_create_secret
from psoperator.config import PSOperatorConfig, load_config
from psoperator.gatekeeper import killswitch
from psoperator.gatekeeper.approval import CLIApproval
from psoperator.gatekeeper.audit import verify
from psoperator.gatekeeper.gatekeeper import Gatekeeper
from psoperator.gatekeeper.remote_executor import RemoteExecutor
from psoperator.perception.snapshot import SnapshotBuilder
from psoperator.runtime.freshness import FreshnessTracker
from psoperator.services.executor import build_executor
from psoperator.services.executor import serve as serve_executor
from psoperator.services.gatekeeper import serve as serve_gatekeeper
from psoperator.services.observer import build_capture as build_observer_capture
from psoperator.services.observer import serve as serve_observer
from psoperator.services.observer_client import ObserverClient, ObserverUnavailable


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psoperator",
        description="Local, policy-gated desktop operator",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("kill", help="engage the global action kill switch")
    commands.add_parser("resume", help="explicitly disengage the kill switch")

    audit = commands.add_parser("audit-verify", help="verify the audit hash chain")
    audit.add_argument("path", nargs="?", type=Path)

    executor = commands.add_parser("executor", help="run the authenticated executor service")
    executor.add_argument("--backend", choices=("dryrun", "pynput", "ch9329"))

    observer = commands.add_parser("observer", help="run independent capture and perception")
    observer.add_argument("--backend", choices=("mss", "uvc"))
    commands.add_parser("observer-health", help="query observer lifecycle health")
    keygen = commands.add_parser(
        "attestation-keygen",
        help="provision a new owner-only observer attestation key",
    )
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--path", type=Path)

    commands.add_parser("gatekeeper", help="run the policy gatekeeper service")
    return parser


def _run_executor(config: PSOperatorConfig, backend: str | None) -> int:
    secret = load_or_create_secret(config.ipc_secret_path)
    selected = backend or config.executor_backend
    executor = build_executor(
        selected,
        port=config.ch9329_port,
        baudrate=config.ch9329_baudrate,
    )
    print(f"executor listening on {config.executor_host}:{config.executor_port} ({executor.name})")
    serve_executor(config.executor_host, config.executor_port, executor, secret)
    return 0


def _run_gatekeeper(config: PSOperatorConfig) -> int:
    secret = load_or_create_secret(config.ipc_secret_path)
    freshness = FreshnessTracker()
    executor = RemoteExecutor(config.executor_host, config.executor_port, secret)
    gatekeeper = Gatekeeper(config, freshness, CLIApproval(), executor)
    print(f"gatekeeper listening on {config.gatekeeper_host}:{config.gatekeeper_port}")
    serve_gatekeeper(config.gatekeeper_host, config.gatekeeper_port, gatekeeper, freshness)
    return 0


def _run_observer(config: PSOperatorConfig, backend: str | None) -> int:
    key_path = config.observer_attestation_key_path
    if key_path is None:
        print("observer unavailable: PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH is required")
        return 2
    try:
        key = load_attestation_key(key_path)
    except AttestationKeyError as exc:
        print(f"observer unavailable: {exc}")
        return 2
    signer = SnapshotSigner(key, ttl_s=config.observer_snapshot_ttl_s)
    snapshots = SnapshotBuilder(max_elements=config.observer_max_elements)
    capture = build_observer_capture(config, backend)
    selected = backend or config.capture_backend
    print(
        f"observer listening on {config.observer_host}:{config.observer_port} ({selected})",
        flush=True,
    )
    serve_observer(config.observer_host, config.observer_port, capture, signer, snapshots)
    return 0


def _run_attestation_keygen(
    config: PSOperatorConfig,
    path: Path | None,
    key_id: str,
) -> int:
    target = path or config.observer_attestation_key_path
    if target is None:
        print("attestation key path is required (--path or configuration)")
        return 2
    try:
        key = provision_attestation_key(target, key_id)
    except (AttestationKeyError, OSError) as exc:
        print(f"attestation key provisioning failed: {exc}")
        return 2
    print(f"provisioned attestation key {key.key_id!r} at {target}")
    return 0


def _run_observer_health(config: PSOperatorConfig) -> int:
    client = ObserverClient(
        config.observer_host,
        config.observer_port,
        timeout=config.observer_timeout_s,
    )
    try:
        health = client.health()
    except ObserverUnavailable as exc:
        print(exc)
        return 1
    print(
        f"{health.status.upper()}: backend={health.backend} "
        f"sequence={health.last_sequence} failures={health.consecutive_failures}"
        + (f" error={health.error}" if health.error else "")
    )
    return 0 if health.status == "ready" else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = load_config()

    if args.command == "kill":
        killswitch.engage(config.kill_switch_path)
        print(f"kill switch engaged: {config.kill_switch_path}")
        return 0
    if args.command == "resume":
        killswitch.disengage(config.kill_switch_path)
        print(f"kill switch disengaged: {config.kill_switch_path}")
        return 0
    if args.command == "audit-verify":
        result = verify(args.path or config.audit_log_path)
        print(
            f"{'OK' if result.ok else 'FAILED'}: {result.lines_checked} records checked"
            + (f" ({result.error})" if result.error else "")
        )
        return 0 if result.ok else 1
    if args.command == "executor":
        return _run_executor(config, args.backend)
    if args.command == "observer":
        return _run_observer(config, args.backend)
    if args.command == "observer-health":
        return _run_observer_health(config)
    if args.command == "attestation-keygen":
        return _run_attestation_keygen(config, args.path, args.key_id)
    if args.command == "gatekeeper":
        return _run_gatekeeper(config)
    raise AssertionError(f"unhandled command {args.command}")
