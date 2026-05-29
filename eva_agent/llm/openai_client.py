"""OpenAI-compatible LLM client for evidence judgment.

Supports OpenAI, Azure OpenAI, and any other OpenAI-compatible API
(e.g. Ollama, vLLM, local推理 endpoints).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI

from eva_agent.llm.client import LLMClient, LLMJudgment
from eva_agent.llm.config import LLMConfig

logger = logging.getLogger(__name__)

_JUDGE_SYSTEM_PROMPT = (
    "You are an expert security analyst evaluating whether an exploit "
    "was successful. You will be given evidence from an exploit execution "
    "sandbox, including command output, exit codes, and SSH verification "
    "results. Analyze the evidence carefully and return a JSON object "
    "with the following fields:\n"
    "- success: boolean (true if the exploit clearly succeeded, false "
    "otherwise)\n"
    "- confidence: float between 0.0 and 1.0 indicating your confidence "
    "in the judgment\n"
    "- reasoning: string explaining your analysis step by step\n\n"
    "Be conservative: if the evidence is ambiguous or inconclusive, "
    "set success to false and provide a low confidence score."
)


class OpenAIClient(LLMClient):
    """An LLM client that uses the OpenAI API (or any OpenAI-compatible
    endpoint) to judge exploit evidence.

    Args:
        config: An ``LLMConfig`` instance with connection details.
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key,
        )
        logger.debug(
            "OpenAIClient initialized: provider=%s model=%s base_url=%s",
            config.provider,
            config.model,
            config.base_url,
        )

    async def judge(self, evidence: dict[str, Any]) -> LLMJudgment:
        """Send evidence to the LLM and parse the structured response.

        Args:
            evidence: A dict containing the evidence to judge.

        Returns:
            An ``LLMJudgment`` with the LLM's evaluation, or a
            fallback judgment if parsing fails.
        """
        evidence_text = json.dumps(evidence, indent=2, ensure_ascii=False)

        try:
            response = await self._client.chat.completions.create(
                model=self._config.model,
                temperature=self._config.temperature,
                max_tokens=500,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": _JUDGE_SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": (
                            "Please evaluate the following exploit "
                            "evidence and determine if the exploit was "
                            f"successful:\n\n{evidence_text}"
                        ),
                    },
                ],
            )
        except Exception:
            logger.exception(
                "LLM API call failed for model %s", self._config.model
            )
            return LLMJudgment(
                success=False,
                confidence=0.0,
                reasoning="Failed to parse LLM response",
            )

        content = response.choices[0].message.content
        if not content:
            logger.warning("LLM returned empty response")
            return LLMJudgment(
                success=False,
                confidence=0.0,
                reasoning="Failed to parse LLM response",
            )

        try:
            parsed: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError:
            logger.warning(
                "Failed to parse LLM response as JSON: %s",
                content[:200],
            )
            return LLMJudgment(
                success=False,
                confidence=0.0,
                reasoning="Failed to parse LLM response",
            )

        success = bool(parsed.get("success", False))
        confidence = float(parsed.get("confidence", 0.0))
        reasoning = str(parsed.get("reasoning", ""))

        # Clamp confidence to [0.0, 1.0]
        confidence = max(0.0, min(1.0, confidence))

        logger.info(
            "LLM judgment: success=%s confidence=%.4f",
            success,
            confidence,
        )
        return LLMJudgment(
            success=success,
            confidence=confidence,
            reasoning=reasoning,
        )
