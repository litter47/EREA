"""Tests for LLM configuration loading and environment variable overrides.

Uses ``monkeypatch.setenv`` to set environment variables and
``tempfile`` / ``pyyaml`` to create temporary YAML configuration
files.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from eva_agent.llm.config import LLMConfig, load_llm_config


class TestLoadDefaultConfig:
    """Tests that ``load_llm_config`` returns sensible defaults when no
    YAML file or environment overrides are present."""

    def test_load_default_config(self):
        """Default config has ``enabled=False``, ``provider="openai"``,
        and default model / base URL."""
        config: LLMConfig = load_llm_config(config_dir="/nonexistent/dir")

        assert config.enabled is False
        assert config.provider == "openai"
        assert config.base_url == "https://api.openai.com/v1"
        assert config.model == "gpt-4.1"
        assert config.temperature == 0.0
        assert config.api_key == ""


class TestLoadFromYaml:
    """Tests that values from a YAML file are loaded correctly."""

    def test_load_from_yaml(self):
        """Config values from a temporary YAML file are reflected in the
        returned ``LLMConfig``."""
        raw_config = {
            "provider": "anthropic",
            "base_url": "https://api.anthropic.com",
            "api_key": "sk-ant-xxxxxxxx",
            "model": "claude-3-opus",
            "temperature": 0.5,
            "enabled": True,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "llm.yaml"
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(raw_config, f)

            config: LLMConfig = load_llm_config(config_dir=tmpdir)

        assert config.provider == "anthropic"
        assert config.base_url == "https://api.anthropic.com"
        assert config.api_key == "sk-ant-xxxxxxxx"
        assert config.model == "claude-3-opus"
        assert config.temperature == 0.5
        assert config.enabled is True


class TestEnvOverrides:
    """Tests that ``EVA_LLM_*`` environment variables override YAML
    values (and defaults)."""

    # ---- Individual overrides -------------------------------------------

    def test_env_override_provider(self, monkeypatch: pytest.MonkeyPatch):
        """``EVA_LLM_PROVIDER`` overrides the YAML value."""
        raw_config = {"provider": "openai", "enabled": True}
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "llm.yaml"
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(raw_config, f)

            monkeypatch.setenv("EVA_LLM_PROVIDER", "azure")
            config: LLMConfig = load_llm_config(config_dir=tmpdir)

        assert config.provider == "azure"
        assert config.enabled is True  # YAML value preserved

    def test_env_override_base_url(self, monkeypatch: pytest.MonkeyPatch):
        """``EVA_LLM_BASE_URL`` overrides the YAML value."""
        raw_config = {"base_url": "https://default.example.com/v1"}
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "llm.yaml"
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(raw_config, f)

            monkeypatch.setenv("EVA_LLM_BASE_URL", "https://custom.example.com")
            config: LLMConfig = load_llm_config(config_dir=tmpdir)

        assert config.base_url == "https://custom.example.com"

    def test_env_override_api_key(self, monkeypatch: pytest.MonkeyPatch):
        """``EVA_LLM_API_KEY`` overrides the YAML value."""
        raw_config = {"api_key": "yaml-key"}
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "llm.yaml"
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(raw_config, f)

            monkeypatch.setenv("EVA_LLM_API_KEY", "env-key-12345")
            config: LLMConfig = load_llm_config(config_dir=tmpdir)

        assert config.api_key == "env-key-12345"

    def test_env_override_model(self, monkeypatch: pytest.MonkeyPatch):
        """``EVA_LLM_MODEL`` overrides the YAML value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "llm.yaml"
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump({"model": "gpt-3.5-turbo"}, f)

            monkeypatch.setenv("EVA_LLM_MODEL", "gpt-4-turbo")
            config: LLMConfig = load_llm_config(config_dir=tmpdir)

        assert config.model == "gpt-4-turbo"

    # ---- Environment variable "enabled" variants ------------------------

    def test_env_enabled_true(self, monkeypatch: pytest.MonkeyPatch):
        """``EVA_LLM_ENABLED=true`` sets ``enabled=True``."""
        monkeypatch.setenv("EVA_LLM_ENABLED", "true")
        config: LLMConfig = load_llm_config(config_dir="/nonexistent/dir")
        assert config.enabled is True

    def test_env_enabled_false(self, monkeypatch: pytest.MonkeyPatch):
        """``EVA_LLM_ENABLED=false`` keeps ``enabled=False``."""
        monkeypatch.setenv("EVA_LLM_ENABLED", "false")
        config: LLMConfig = load_llm_config(config_dir="/nonexistent/dir")
        assert config.enabled is False

    # ---- Missing / fallback ---------------------------------------------

    def test_missing_yaml_uses_env_only(self, monkeypatch: pytest.MonkeyPatch):
        """When the YAML file does not exist, defaults are used and env
        vars still apply."""
        monkeypatch.setenv("EVA_LLM_PROVIDER", "env-only-provider")
        monkeypatch.setenv("EVA_LLM_ENABLED", "true")

        # Point config_dir to a directory that does not exist
        config: LLMConfig = load_llm_config(config_dir="/tmp/__eva_test_no_such_dir__")

        assert config.provider == "env-only-provider"
        assert config.enabled is True
        # Defaults for the rest
        assert config.base_url == "https://api.openai.com/v1"
        assert config.model == "gpt-4.1"
        assert config.temperature == 0.0
