"""LLM configuration, loaded from YAML and overridable via environment
variables with the ``EVA_LLM_`` prefix.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Environment variable names
_ENV_PROVIDER = "EVA_LLM_PROVIDER"
_ENV_BASE_URL = "EVA_LLM_BASE_URL"
_ENV_API_KEY = "EVA_LLM_API_KEY"
_ENV_MODEL = "EVA_LLM_MODEL"
_ENV_TEMPERATURE = "EVA_LLM_TEMPERATURE"
_ENV_ENABLED = "EVA_LLM_ENABLED"


@dataclass
class LLMConfig:
    """Configuration for an LLM-based judgment client.

    Attributes:
        provider: The LLM provider name (e.g. ``"openai"``).
        base_url: Base URL for the provider's API.
        api_key: API key for authentication.
        model: Model identifier (e.g. ``"gpt-4.1"``).
        temperature: Sampling temperature (0.0 = deterministic).
        enabled: Whether LLM judgment is active.
    """

    provider: str = "openai"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4.1"
    temperature: float = 0.0
    enabled: bool = False


def _env_overrides(config: LLMConfig) -> LLMConfig:
    """Apply environment variable overrides to an existing LLMConfig.

    … and return the (mutated) config for convenience.
    """
    if _env_val := os.environ.get(_ENV_PROVIDER, "").strip():
        config.provider = _env_val
    if _env_val := os.environ.get(_ENV_BASE_URL, "").strip():
        config.base_url = _env_val
    if _env_val := os.environ.get(_ENV_API_KEY, "").strip():
        config.api_key = _env_val
    if _env_val := os.environ.get(_ENV_MODEL, "").strip():
        config.model = _env_val
    if _env_val := os.environ.get(_ENV_TEMPERATURE, "").strip():
        try:
            config.temperature = float(_env_val)
        except ValueError:
            logger.warning(
                "Invalid EVA_LLM_TEMPERATURE value '%s', ignoring",
                _env_val,
            )
    if _env_val := os.environ.get(_ENV_ENABLED, "").strip().lower():
        config.enabled = _env_val in ("true", "1", "yes")
    return config


def _make_default_config() -> LLMConfig:
    """Create a default ``LLMConfig`` from environment variables only."""
    return _env_overrides(LLMConfig())


def load_llm_config(config_dir: str = "config") -> LLMConfig:
    """Load LLM configuration, merging YAML file with env-var overrides.

    Resolution order (later overrides earlier):
        1. Default values in ``LLMConfig``
        2. Values from ``config_dir/llm.yaml`` (if it exists)
        3. Environment variables with the ``EVA_LLM_`` prefix

    Args:
        config_dir: Path to the configuration directory. Defaults to
            ``"config"`` relative to the current working directory.

    Returns:
        A fully resolved ``LLMConfig`` instance.
    """
    # Absolute path for robustness
    config_path = Path(config_dir).resolve() / "llm.yaml"

    if config_path.is_file():
        logger.info("Loading LLM config from %s", config_path)
        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                raw: dict[str, Any] = yaml.safe_load(fh) or {}
        except Exception:
            logger.exception(
                "Failed to parse %s, falling back to env defaults",
                config_path,
            )
            return _make_default_config()

        config = LLMConfig(
            provider=raw.get("provider", LLMConfig.provider),
            base_url=raw.get("base_url", LLMConfig.base_url),
            api_key=raw.get("api_key", LLMConfig.api_key),
            model=raw.get("model", LLMConfig.model),
            temperature=float(
                raw.get("temperature", LLMConfig.temperature)
            ),
            enabled=bool(raw.get("enabled", LLMConfig.enabled)),
        )
    else:
        logger.info(
            "LLM config not found at %s, using env defaults", config_path
        )
        config = LLMConfig()

    # Environment variables always take highest priority
    return _env_overrides(config)
