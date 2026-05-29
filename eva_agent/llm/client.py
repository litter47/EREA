"""Abstract base class and data structures for LLM-based judgment.

The LLM client hierarchy allows plugging in different providers
(e.g. OpenAI, Azure, local models) behind a common interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMJudgment:
    """Structured judgment returned by an LLM after evaluating evidence.

    Attributes:
        success: Whether the LLM judged the exploit as successful.
        confidence: Confidence level of the judgment (0.0 to 1.0).
        reasoning: Free-text explanation of the LLM's reasoning.
    """

    success: bool
    confidence: float  # 0.0 - 1.0
    reasoning: str = ""


class LLMClient(ABC):
    """Abstract base for all LLM-based judgment clients.

    Subclasses must implement the ``judge()`` method.
    """

    @abstractmethod
    async def judge(self, evidence: dict[str, Any]) -> LLMJudgment:
        """Evaluate a single piece of evidence and return a judgment.

        Args:
            evidence: A dict containing the evidence to be judged,
                typically with keys such as ``type``, ``source``,
                ``data``, and ``timestamp``.

        Returns:
            An ``LLMJudgment`` instance with the LLM's evaluation.
        """
        ...
