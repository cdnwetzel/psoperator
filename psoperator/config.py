"""Runtime configuration for PSOperator.

Fully local by construction: the only network target is an OpenAI-compatible
HTTP endpoint (llama.cpp / vLLM serving a local GUI model). There are no
cloud credentials in this codebase, and none are accepted here.
"""

from __future__ import annotations

import ipaddress
import tomllib
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from psoperator.common.schema import MAX_SNAPSHOT_ELEMENTS, MAX_SNAPSHOT_TTL_SECONDS

# Fleet addressing invariants (operator-provided ground truth; do not relax).
# These fleet presets are a SPECIFIC deployment's EXAMPLE, not portable defaults
# (see README): the addresses are RFC-5737 documentation placeholders and the
# fail-closed invariants below are pinned to them. For a real deployment,
# configure via PSOPERATOR_* env / .env starting from the localhost default
# (load_config) rather than loading these example presets — from_preset() passes
# preset values as explicit constructor arguments that take precedence over env,
# so env does NOT override a loaded preset.
# HOME: the planner is reachable ONLY through the governed audit proxy at
# 10.0.1.125:8003. Port 8004 bypasses the proxy (no audit), the hostname
# "precision-t5810" is not pinnable to the governed host, and 10.0.1.51 is a
# stale, wrong address. WORK: everything is routed via the psrouter at
# 203.0.113.10:8888/v1; unrouted LAN endpoints are out-of-policy.
# The two fleets must never reference each other's networks (10.0.1.0/24 vs
# 203.0.113.0/24).
HOME_PLANNER_URL = "http://10.0.1.125:8003/v1"
HOME_PLANNER_HOSTNAME = "precision-t5810"
HOME_PLANNER_STALE_IP = "10.0.1.51"
WORK_PSROUTER_URL = "http://203.0.113.10:8888/v1"
HOME_NET = ipaddress.ip_network("10.0.1.0/24")
WORK_NET = ipaddress.ip_network("203.0.113.0/24")

_PRESETS_DIR = Path(__file__).resolve().parent / "presets"


class ConfigError(ValueError):
    """Raised when a config or fleet preset violates an addressing invariant."""


class PSOperatorConfig(BaseSettings):
    """All settings are overridable via ``PSOPERATOR_`` env vars or a .env file."""

    model_config = SettingsConfigDict(env_prefix="PSOPERATOR_", env_file=".env", extra="ignore")

    # --- model endpoint (the ONLY allowed network call) -------------------
    model_endpoint: str = Field(
        default="http://localhost:8000/v1",
        description="OpenAI-compatible base URL of a local server "
        "(llama.cpp / vLLM serving e.g. UI-TARS-1.5-7B GGUF or Holo3.1-4B).",
    )
    model_name: str = Field(default="ui-tars-1.5-7b", description="Model id sent in the request.")
    model_timeout_s: float = Field(default=60.0, description="Per-request timeout.")
    model_api_key: str = Field(
        default="not-needed",
        description="Local servers ignore this; kept only for client compatibility.",
    )
    planner_ctx_budget: int = Field(
        default=8192,
        description="Planner model context budget (tokens); prompts/history are "
        "trimmed to fit. Must match what the served model is actually run with.",
    )
    grounder_url: str | None = Field(
        default=None,
        description="OpenAI-compatible base URL of the grounding model "
        "(e.g. Ollama serving holo3.1:4b). None = planner grounds for itself.",
    )
    grounder_model: str | None = Field(
        default=None, description="Model id sent to the grounder endpoint."
    )

    # --- perception --------------------------------------------------------
    capture_backend: str = Field(
        default="mss",
        description="Screen capture backend. 'mss' works everywhere (Topology A); "
        "'uvc' reads a USB HDMI capture card (Topology B / crash-cart mode). "
        "Production impls: DXGI (Windows), ScreenCaptureKit (macOS), PipeWire (Linux).",
    )
    monitor: int = Field(default=1, description="Monitor index for the mss capture backend.")
    tile_size: int = Field(default=32, description="Tile edge (px) for frame diffing.")
    diff_threshold: float = Field(
        default=0.01, description="Min fraction of changed tiles before a frame is 'dirty'."
    )
    phash_threshold: int = Field(
        default=6, description="Max phash hamming distance for two frames to count as same scene."
    )
    observer_host: str = Field(default="127.0.0.1")
    observer_port: int = Field(default=8764, ge=1, le=65535)
    observer_timeout_s: float = Field(default=5.0, gt=0, le=60.0)
    observer_max_elements: int = Field(
        default=MAX_SNAPSHOT_ELEMENTS, ge=1, le=MAX_SNAPSHOT_ELEMENTS
    )
    observer_attestation_key_path: Path | None = Field(
        default=None,
        description="Owner-only key file provisioned under the observer service account. "
        "Required to start the observer; never auto-created by service startup.",
    )
    observer_snapshot_ttl_s: float = Field(
        default=10.0,
        gt=0,
        le=MAX_SNAPSHOT_TTL_SECONDS,
        description="Lifetime of a signed observer snapshot envelope.",
    )

    # --- Topology B (crash-cart / out-of-band) ------------------------------
    uvc_device_index: int = Field(
        default=0,
        description="UVC capture card index (/dev/videoN). Only for capture_backend='uvc'.",
    )
    uvc_width: int = Field(default=1920, description="Requested UVC capture width (px).")
    uvc_height: int = Field(default=1080, description="Requested UVC capture height (px).")
    executor_backend: str = Field(
        default="dryrun",
        description="Input executor backend. 'dryrun' (default, safe) | 'pynput' "
        "(same-machine OS input, opt-in) | 'ch9329' (out-of-band HID over serial, "
        "Topology B). All still behind the gatekeeper.",
    )
    ch9329_port: str = Field(
        default="/dev/ttyUSB0", description="Serial port of the CH9329 HID cable."
    )
    ch9329_baudrate: int = Field(
        default=9600,
        description="CH9329 factory default is 9600; 115200 only works after the "
        "chip itself has been reconfigured. Must match the chip, not the wish.",
    )

    # --- policy / gatekeeper ----------------------------------------------
    risk_policy_path: Path = Field(
        default=Path("policy.json"),
        description="JSON file with extra T2/T3 keyword patterns; merged over built-ins.",
    )
    audit_log_path: Path = Field(default=Path("psoperator_audit.jsonl"))
    kill_switch_path: Path = Field(default=Path(".psoperator/STOP"))
    ipc_secret_path: Path = Field(default=Path(".psoperator/ipc.secret"))
    gatekeeper_host: str = Field(default="127.0.0.1")
    gatekeeper_port: int = Field(default=8765, ge=1, le=65535)
    executor_host: str = Field(default="127.0.0.1")
    executor_port: int = Field(default=8766, ge=1, le=65535)
    require_approval_for_t2: bool = Field(default=True)
    hard_block_t3: bool = Field(
        default=True,
        description="Hard-block destructive T3 actions. Disable only by explicit operator policy.",
    )
    require_approval_for_t3: bool = Field(
        default=True,
        description="When hard_block_t3 is disabled, still require explicit approval for T3.",
    )

    # --- memory / retrieval services (optional, off by default) ------------
    embeddings_url: str | None = Field(
        default=None,
        description="Embeddings endpoint (e.g. bge-base-en-v1.5 / bge-m3). "
        "If loopback (127.0.0.1), memory components must co-locate on that host.",
    )
    qdrant_url: str | None = Field(
        default=None, description="Qdrant vector-store endpoint for skill/memory retrieval."
    )
    reranker_url: str | None = Field(
        default=None, description="Reranker endpoint (e.g. bge-reranker-base)."
    )
    ocr_url: str | None = Field(
        default=None,
        description="OCR service endpoint (e.g. gpu-ocr / PaddleOCR). "
        "None = in-process OCR (rapidocr) if installed.",
    )

    # --- remote notify (optional, off by default) --------------------------
    ntfy_url: str | None = Field(
        default=None, description="e.g. https://ntfy.sh/my-topic. None disables push approvals."
    )

    # --- fleet presets ------------------------------------------------------
    @classmethod
    def from_preset(cls, name_or_path: str | Path) -> "PSOperatorConfig":
        """Load a TOML fleet preset over the defaults and validate it.

        ``name_or_path`` may be a path to a TOML file, a filename inside the
        repo's ``presets/`` dir, or a short fleet name (``"home"``/``"work"``,
        resolved to ``presets/config.fleet-<name>.toml``). The fleet is taken
        from the preset's ``fleet`` key or inferred from the filename.
        Addressing invariants are enforced fail-closed: a violation raises
        :class:`ConfigError` and no config is returned.
        """
        path = _resolve_preset_path(name_or_path)
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        fleet = data.pop("fleet", None)
        if fleet is None:
            stem = path.stem.lower()
            if "home" in stem:
                fleet = "home"
            elif "work" in stem:
                fleet = "work"
        cfg = cls(**data)
        if fleet is not None:
            _validate_fleet_addressing(cfg, str(fleet).lower(), source=str(path))
        return cfg


def _resolve_preset_path(name_or_path: str | Path) -> Path:
    path = Path(name_or_path)
    if path.is_file():
        return path
    for candidate in (
        _PRESETS_DIR / str(name_or_path),
        _PRESETS_DIR / f"config.fleet-{name_or_path}.toml",
    ):
        if candidate.is_file():
            return candidate
    raise ConfigError(
        f"Preset not found: {name_or_path!r} (looked as a path and under {_PRESETS_DIR})"
    )


def _host_ip(url: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the URL's host as an IP literal, or None for hostnames/invalid."""
    try:
        return ipaddress.ip_address(urlparse(url).hostname or "")
    except ValueError:
        return None


def _fleet_urls(cfg: PSOperatorConfig) -> dict[str, str]:
    return {
        name: url
        for name, url in {
            "model_endpoint": cfg.model_endpoint,
            "grounder_url": cfg.grounder_url,
            "embeddings_url": cfg.embeddings_url,
            "qdrant_url": cfg.qdrant_url,
            "reranker_url": cfg.reranker_url,
            "ocr_url": cfg.ocr_url,
            "ntfy_url": cfg.ntfy_url,
        }.items()
        if url
    }


def _reject_cross_fleet(
    urls: dict[str, str], net: ipaddress.IPv4Network, fleet: str, other: str, source: str
) -> None:
    for field, url in urls.items():
        ip = _host_ip(url)
        if ip is not None and ip in net:
            raise ConfigError(
                f"{fleet} preset ({source}) field {field}={url!r} references the "
                f"{other} fleet network {net}. Fleets must not cross-reference; the "
                "only documented exception (the 7960:8003 tunnel) is intentionally "
                "not encoded in any preset."
            )


def _validate_fleet_addressing(cfg: PSOperatorConfig, fleet: str, source: str) -> None:
    urls = _fleet_urls(cfg)
    if fleet == "home":
        ep = cfg.model_endpoint
        if ep != HOME_PLANNER_URL:
            parsed = urlparse(ep)
            host, port = parsed.hostname, parsed.port
            if port == 8004:
                raise ConfigError(
                    f"Home preset ({source}) uses planner port 8004 ({ep!r}). That "
                    "port bypasses the governed audit proxy: all home planner "
                    f"traffic must traverse {HOME_PLANNER_URL} so every request is "
                    "audited. There is no ungoverned path to the planner."
                )
            if host == HOME_PLANNER_HOSTNAME:
                raise ConfigError(
                    f"Home preset ({source}) addresses the planner by hostname "
                    f"{HOME_PLANNER_HOSTNAME!r}. Hostnames are not pinnable to the "
                    f"governed host; use the literal {HOME_PLANNER_URL}."
                )
            if host == HOME_PLANNER_STALE_IP:
                raise ConfigError(
                    f"Home preset ({source}) uses stale planner address "
                    f"{HOME_PLANNER_STALE_IP}. The governed planner proxy lives at "
                    f"{HOME_PLANNER_URL}."
                )
            raise ConfigError(
                f"Home preset ({source}) model_endpoint must be exactly "
                f"{HOME_PLANNER_URL} (governed audit proxy); got {ep!r}."
            )
        _reject_cross_fleet(urls, WORK_NET, "home", "work", source)
    elif fleet == "work":
        ep = cfg.model_endpoint
        if ep != WORK_PSROUTER_URL:
            ip = _host_ip(ep)
            if ip is not None and ip in HOME_NET:
                raise ConfigError(
                    f"Work preset ({source}) model_endpoint {ep!r} references the "
                    "home fleet network 10.0.1.0/24. Fleets must not cross-reference."
                )
            raise ConfigError(
                f"Work preset ({source}) model_endpoint must route via the psrouter "
                f"at {WORK_PSROUTER_URL}; bare-proc and unrouted LAN endpoints are "
                f"out-of-policy. Got {ep!r}."
            )
        _reject_cross_fleet(urls, HOME_NET, "work", "home", source)
    else:
        raise ConfigError(f"Unknown fleet {fleet!r} in preset {source}; expected 'home' or 'work'.")


def load_preset(name_or_path: str | Path) -> PSOperatorConfig:
    """Module-level convenience wrapper for :meth:`PSOperatorConfig.from_preset`."""
    return PSOperatorConfig.from_preset(name_or_path)


def load_config(**overrides) -> PSOperatorConfig:
    """Build a config, applying explicit overrides last (useful in tests)."""
    return PSOperatorConfig(**overrides)
