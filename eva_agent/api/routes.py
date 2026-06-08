"""FastAPI router for the EVA-Agent HTTP API.

Endpoints
---------
* ``POST /submit``    -- submit an exploit file for verification.
* ``GET  /task/{id}`` -- poll the current status of a task.
* ``GET  /result/{id}`` -- retrieve the final result of a task.
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from eva_agent.api.dependencies import get_settings, get_task_manager
from eva_agent.api.models import (
    ResultResponse,
    SubmitResponse,
    TaskStatusResponse,
    VerifyBackend,
    VerifyType,
)
from eva_agent.config.settings import Settings
from eva_agent.task.manager import TaskManager
from eva_agent.task.models import Task, TaskStatus

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/submit", response_model=SubmitResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_exploit(
    exploit_file: UploadFile = File(..., description="The exploit binary / script to verify"),
    execute_cmd: str = Form(..., description="Command used to run the exploit inside the sandbox"),
    target_ip: str = Form(..., description="IP address of the target container / host"),
    target_port: int = Form(..., description="Port of the target service"),
    verify_type: VerifyType = Form(..., description="Category of the vulnerability being verified"),
    ssh_user: str = Form(..., description="SSH/WinRM username for the target"),
    ssh_password: Optional[str] = Form(None, description="SSH/WinRM password (alternative to key)"),
    ssh_key: Optional[str] = Form(None, description="SSH private key content (alternative to password)"),
    verify_backend: VerifyBackend = Form(VerifyBackend.ssh, description="Verification backend: ssh, docker, winrm, or http"),
    container_name: Optional[str] = Form(None, description="Docker container name (required when verify_backend=docker)"),
    generate_rules_with_llm: bool = Form(False, description="Generate verification rules with the configured LLM before falling back to YAML rules"),
    settings: Settings = Depends(get_settings),
    manager: TaskManager = Depends(get_task_manager),
) -> SubmitResponse:
    """Accept an exploit file and enqueue it for verification.

    The exploit is saved to ``{upload_dir}/{task_id}/exploit`` and a
    ``Task`` is created with the supplied metadata.  The returned
    ``task_id`` can be used with the ``GET /task/{id}`` and
    ``GET /result/{id}`` endpoints.
    """
    if not exploit_file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a non-empty filename.",
        )

    # ------------------------------------------------------------------
    # Build the request dictionary that will be persisted with the task.
    # This captures everything needed for execution without coupling
    # the API layer to low-level execution internals.
    # ------------------------------------------------------------------
    task_id = str(uuid.uuid4())
    upload_subdir = os.path.join(settings.upload_dir, task_id)
    os.makedirs(upload_subdir, exist_ok=True)
    destination = os.path.join(upload_subdir, "exploit")
    source_language = _detect_source_language(exploit_file.filename)

    try:
        content = await exploit_file.read()
        with open(destination, "wb") as f:
            f.write(content)
    except OSError as exc:
        logger.error("Failed to write uploaded file to %s: %s", destination, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not persist uploaded file: {exc}",
        )

    logger.info(
        "Exploit file '%s' (%d bytes) saved to %s",
        exploit_file.filename,
        len(content),
        destination,
    )

    request: dict = {
        "execute_cmd": execute_cmd,
        "target_ip": target_ip,
        "target_port": target_port,
        "verify_type": verify_type.value,
        "verify_backend": verify_backend.value,
        "ssh_user": ssh_user,
        "generate_rules_with_llm": generate_rules_with_llm,
    }
    if source_language is not None:
        request["source_language"] = source_language
    if exploit_file.filename is not None:
        request["original_filename"] = exploit_file.filename
    if ssh_password is not None:
        request["ssh_password"] = ssh_password
    if ssh_key is not None:
        request["ssh_key"] = ssh_key
    if container_name is not None:
        request["container_name"] = container_name

    task = Task(id=task_id, request=request, file_path=destination)
    manager.submit(task)

    return SubmitResponse(
        task_id=task_id,
        status=task.status.value,
        message="Task accepted and queued for execution.",
    )


@router.get(
    "/task/{task_id}",
    response_model=TaskStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def get_task_status(
    task_id: str,
    manager: TaskManager = Depends(get_task_manager),
) -> TaskStatusResponse:
    """Return the current status of a previously submitted task."""
    task = manager.get(task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task '{task_id}' not found.",
        )

    return TaskStatusResponse(
        task_id=task.id,
        status=task.status.value,
        created_at=task.created_at.isoformat(),
        updated_at=task.updated_at.isoformat() if task.updated_at else None,
    )


@router.get(
    "/result/{task_id}",
    response_model=ResultResponse,
    status_code=status.HTTP_200_OK,
)
async def get_task_result(
    task_id: str,
    manager: TaskManager = Depends(get_task_manager),
) -> ResultResponse:
    """Return the final result of a completed task.

    If the task is still running the ``result`` field will be ``None``.
    """
    task = manager.get(task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task '{task_id}' not found.",
        )

    result_dict: Optional[dict] = None
    if task.result is not None:
        result_dict = _task_result_to_dict(task.result)

    return ResultResponse(
        task_id=task.id,
        status=task.status.value,
        result=result_dict,
    )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _task_result_to_dict(result: TaskResult) -> dict:
    """Convert a ``TaskResult`` dataclass to a JSON-serialisable dict."""
    from dataclasses import asdict

    raw = asdict(result)

    # Remove keys whose values are None so the API response is compact.
    cleaned: dict = {}
    for key, value in raw.items():
        if value is not None:
            cleaned[key] = value
    return cleaned


def _detect_source_language(filename: str | None) -> str | None:
    """Infer source language from the uploaded filename extension."""
    suffix = Path(filename or "").suffix.lower()
    if suffix == ".c":
        return "c"
    if suffix in {".cc", ".cpp", ".cxx", ".c++"}:
        return "cpp"
    if suffix == ".go":
        return "go"
    return None
