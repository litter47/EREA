"""Pydantic request / response models for the EVA-Agent HTTP API."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class VerifyType(str, Enum):
    """Type of exploit verification to perform."""

    rce = "rce"
    info_leak = "info_leak"
    priv_esc = "priv_esc"
    auth_bypass = "auth_bypass"


class VerifyBackend(str, Enum):
    """Verification backend used to reach the target.

    - ``ssh``    : Connect via SSH (password or key).
    - ``docker`` : Execute commands via ``docker exec`` (no SSH needed).
    - ``winrm``  : Connect via WinRM (Windows targets).
    - ``http``   : HTTP-only verification (no shell access).
    """

    ssh = "ssh"
    docker = "docker"
    winrm = "winrm"
    http = "http"


class SubmitResponse(BaseModel):
    """Response returned immediately after a task is submitted."""

    task_id: str = Field(..., description="Unique identifier for the task")
    status: str = Field(..., description="Initial task status")
    message: str = Field(..., description="Human-readable status message")


class TaskStatusResponse(BaseModel):
    """Status of a previously submitted task."""

    task_id: str = Field(..., description="Unique identifier for the task")
    status: str = Field(..., description="Current task status")
    created_at: str = Field(..., description="ISO-8601 creation timestamp")
    updated_at: Optional[str] = Field(
        None, description="ISO-8601 last-updated timestamp"
    )


class ResultResponse(BaseModel):
    """Full result payload for a completed task."""

    task_id: str = Field(..., description="Unique identifier for the task")
    status: str = Field(..., description="Final task status")
    result: Optional[dict] = Field(
        None, description="Structured result data (None if not yet complete)"
    )
