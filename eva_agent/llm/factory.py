"""Factory for creating LLM client instances based on configuration.

The factory checks whether LLM judgment is enabled and whether the
necessary credentials are available before constructing a client.
"""

from __future__ import annotations

import logging
from typing import Optional

from eva_agent.llm.client import LLMClient
from eva_agent.llm.config import LLMConfig
from eva_agent.llm.openai_client import OpenAIClient

logger = logging.getLogger(__name__)


class LLMClientFactory:
    """Factory that produces ``LLMClient`` instances from ``LLMConfig``.

    Usage::

        config = load_llm_config()
        client = LLMClientFactory.create(config)
        if client is not None:
            judgment = await client.judge(evidence)
    """

    @staticmethod
    def create(config: LLMConfig) -> Optional[LLMClient]:
        """Create an LLM client based on the provided configuration.

        Returns ``None`` (with a logged warning) when:
            - ``config.enabled`` is ``False``
            - ``config.api_key`` is empty or whitespace-only

        Currently supported providers (all via the OpenAI-compatible
        client):
            - ``openai`` (and any OpenAI-compatible endpoint)

        Args:
            config: A fully resolved ``LLMConfig`` instance.

        Returns:
            An ``LLMClient`` instance, or ``None`` if LLM judgment is
            disabled or misconfigured.
        """
        if not config.enabled:
            logger.info(
                "LLM judgment is disabled (config.enabled=False)"
            )
            return None

        if not config.api_key.strip():
            logger.warning(
                "LLM judgment is enabled but no API key is configured. "
                "Set EVA_LLM_API_KEY or populate the api_key field in "
                "the LLM config."
            )
            return None

        logger.info(
            "Creating LLM client: provider=%s model=%s",
            config.provider,
            config.model,
        )

        # The OpenAIClient works with any OpenAI-compatible provider
        # (e.g. OpenAI, Azure, Ollama, vLLM, etc.).
        return OpenAIClient(config)
