"""Data models for task lifecycle and result storage.

All models are plain Python dataclasses (not Pydantic). They are used
internally by the task manager, sandbox executor, rule engine, LLM
judge, and report generator.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class TaskStatus(str, Enum):
    """Possible states of a verification task."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


@dataclass
class ExpResult:
    """Raw output from the sandboxed exploit execution."""

    stdout: str
    stderr: str
    exit_code: int
    duration: float  # seconds


@dataclass
class SSHCheck:
    """Result of a single SSH-based verification check."""

    check_name: str
    passed: bool
    details: str


@dataclass
class RuleScore:
    """Rule-engine scoring result."""

    score: float
    passed: bool
    matched_rules: list[str] = field(default_factory=list)


@dataclass
class LLMJudgment:
    """Judgement produced by an LLM (if enabled)."""

    success: bool
    confidence: float
    reasoning: str


@dataclass
class TaskResult:
    """Aggregated result of a completed exploit-verification task."""

    exp_result: Optional[ExpResult] = None
    ssh_checks: list[SSHCheck] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    rule_score: Optional[RuleScore] = None
    llm_judgment: Optional[LLMJudgment] = None
    final_verdict: str = "UNDETERMINED"
    report_json: Optional[dict] = None
    report_md: Optional[str] = None


@dataclass
class Task:
    """A single exploit-verification task tracked through its lifecycle."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request: dict = field(default_factory=dict)
    file_path: str = ""
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: Optional[datetime] = None
    result: Optional[TaskResult] = None
