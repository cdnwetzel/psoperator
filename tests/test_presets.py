"""Fleet presets: both load, and addressing invariants fail closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from psoperator.config import (
    HOME_PLANNER_URL,
    WORK_PSROUTER_URL,
    ConfigError,
    PSOperatorConfig,
    load_preset,
)

PRESETS = Path(__file__).resolve().parent.parent / "psoperator" / "presets"
HOME = PRESETS / "config.fleet-home.toml"
WORK = PRESETS / "config.fleet-work.toml"


def _mutate(tmp_path: Path, src: Path, old: str, new: str) -> Path:
    """Copy a preset with one substitution, keeping the fleet-inferring name."""
    out = tmp_path / src.name
    text = src.read_text(encoding="utf-8")
    assert old in text
    out.write_text(text.replace(old, new), encoding="utf-8")
    return out


# ------------------------------------------------------------------ loading
class TestPresetsLoad:
    def test_home_preset_loads_by_name(self):
        cfg = PSOperatorConfig.from_preset("home")
        assert cfg.model_endpoint == HOME_PLANNER_URL
        assert cfg.model_name == "qwen2.5-coder-14b-pscode"
        assert cfg.model_api_key == "not-needed"
        assert cfg.embeddings_url == "http://127.0.0.1:8005"
        assert cfg.qdrant_url == "http://127.0.0.1:6333"
        assert cfg.reranker_url == "http://10.0.1.115:8006"
        assert cfg.grounder_url == "http://mac-mini:11434/v1"

    def test_work_preset_loads_by_name(self):
        cfg = PSOperatorConfig.from_preset("work")
        assert cfg.model_endpoint == WORK_PSROUTER_URL
        assert cfg.model_name == "Qwen3-Coder"
        assert cfg.grounder_url == WORK_PSROUTER_URL  # grounder routed via psrouter
        assert cfg.embeddings_url == "http://127.0.0.1:11434"
        assert cfg.ocr_url == "http://203.0.113.10:8089"

    def test_load_preset_wrapper_and_path_form(self):
        assert load_preset(HOME).model_endpoint == HOME_PLANNER_URL
        assert load_preset(WORK).model_endpoint == WORK_PSROUTER_URL

    def test_ctx_budgets_parse_as_ints(self):
        home, work = load_preset("home"), load_preset("work")
        assert isinstance(home.planner_ctx_budget, int) and home.planner_ctx_budget == 16384
        assert isinstance(work.planner_ctx_budget, int) and work.planner_ctx_budget == 131072

    def test_presets_keep_safe_defaults(self):
        for name in ("home", "work"):
            cfg = load_preset(name)
            assert cfg.capture_backend == "mss"  # Topology A default
            assert cfg.executor_backend == "dryrun"  # safe default, behind gatekeeper
            assert cfg.require_approval_for_t2 and cfg.require_approval_for_t3

    def test_grounder_placeholder_is_a_note_not_a_failure(self):
        # holo3.1:4b is documented as not yet stood up; loading must still succeed.
        cfg = load_preset("home")
        assert cfg.grounder_model == "holo3.1:4b"
        # work grounder_model intentionally unset (comment only)
        assert load_preset("work").grounder_model is None

    def test_missing_preset_raises(self):
        with pytest.raises(ConfigError, match="Preset not found"):
            load_preset("fleet-nope")


# ------------------------------------------------------------------ home invariants
class TestHomeAddressing:
    def test_rejects_port_8004_ungoverned(self, tmp_path):
        bad = _mutate(tmp_path, HOME, "http://10.0.1.125:8003/v1", "http://10.0.1.125:8004/v1")
        with pytest.raises(ConfigError, match="governed audit proxy"):
            load_preset(bad)

    def test_rejects_hostname(self, tmp_path):
        bad = _mutate(tmp_path, HOME, "http://10.0.1.125:8003/v1", "http://precision-t5810:8003/v1")
        with pytest.raises(ConfigError, match="hostname"):
            load_preset(bad)

    def test_rejects_stale_ip(self, tmp_path):
        bad = _mutate(tmp_path, HOME, "http://10.0.1.125:8003/v1", "http://10.0.1.51:8003/v1")
        with pytest.raises(ConfigError, match="stale"):
            load_preset(bad)

    def test_rejects_any_other_planner_url(self, tmp_path):
        bad = _mutate(tmp_path, HOME, "http://10.0.1.125:8003/v1", "http://10.0.1.125:9000/v1")
        with pytest.raises(ConfigError, match="must be exactly"):
            load_preset(bad)

    @pytest.mark.parametrize(
        "field_line",
        [
            (
                'reranker_url = "http://10.0.1.115:8006"',
                'reranker_url = "http://203.0.113.10:8006"',
            ),
            ('qdrant_url = "http://127.0.0.1:6333"', 'qdrant_url = "http://203.0.113.20:6333"'),
        ],
    )
    def test_rejects_cross_fleet_work_ips(self, tmp_path, field_line):
        bad = _mutate(tmp_path, HOME, field_line[0], field_line[1])
        with pytest.raises(ConfigError, match="cross-reference"):
            load_preset(bad)


# ------------------------------------------------------------------ work invariants
class TestWorkAddressing:
    def test_rejects_home_planner_ip(self, tmp_path):
        bad = _mutate(tmp_path, WORK, WORK_PSROUTER_URL, HOME_PLANNER_URL)
        with pytest.raises(ConfigError, match="home fleet network"):
            load_preset(bad)

    def test_rejects_unrouted_planner(self, tmp_path):
        bad = _mutate(tmp_path, WORK, WORK_PSROUTER_URL, "http://203.0.113.10:8000/v1")
        with pytest.raises(ConfigError, match="psrouter"):
            load_preset(bad)

    def test_rejects_cross_fleet_home_ip_in_services(self, tmp_path):
        bad = _mutate(
            tmp_path,
            WORK,
            'ocr_url = "http://203.0.113.10:8089"',
            'ocr_url = "http://10.0.1.115:8089"',
        )
        with pytest.raises(ConfigError, match="cross-reference"):
            load_preset(bad)


# ------------------------------------------------------------------ misc
class TestPresetMechanics:
    def test_unknown_fleet_key_fails_closed(self, tmp_path):
        p = tmp_path / "config.fleet-mars.toml"
        p.write_text('fleet = "mars"\nmodel_endpoint = "http://x/v1"\n', encoding="utf-8")
        with pytest.raises(ConfigError, match="Unknown fleet"):
            load_preset(p)

    def test_extra_keys_ignored(self, tmp_path):
        p = tmp_path / "config.fleet-home.toml"
        p.write_text(
            HOME.read_text(encoding="utf-8") + '\noperator_note = "hello"\n', encoding="utf-8"
        )
        assert load_preset(p).model_endpoint == HOME_PLANNER_URL

    def test_env_configures_without_a_preset(self, monkeypatch):
        # The documented real-deployment override path: configure via PSOPERATOR_*
        # env / .env (load_config / PSOperatorConfig), NOT by loading an example
        # preset — a preset's explicit constructor args outrank env, so env cannot
        # override a loaded preset. This path (no preset) works and is respected.
        monkeypatch.setenv("PSOPERATOR_MODEL_ENDPOINT", "http://127.0.0.1:8000/v1")
        monkeypatch.setenv("PSOPERATOR_MODEL_NAME", "my-local-model")
        cfg = PSOperatorConfig(_env_file=None)
        assert cfg.model_endpoint == "http://127.0.0.1:8000/v1"
        assert cfg.model_name == "my-local-model"

    def test_preset_args_outrank_env(self, monkeypatch):
        # The precedence the config comment documents: from_preset() passes preset
        # values as explicit constructor args, which WIN over PSOPERATOR_* env, so
        # env cannot override a loaded preset. (Regression for the Major finding —
        # the old comment falsely promised env override of a preset.)
        monkeypatch.setenv("PSOPERATOR_MODEL_NAME", "env-model-should-not-win")
        cfg = PSOperatorConfig.from_preset("work")
        assert cfg.model_name == "Qwen3-Coder"  # preset value, env ignored
        assert cfg.model_endpoint == WORK_PSROUTER_URL
