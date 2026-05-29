"""Shared pytest fixtures for the EVA-Agent test suite."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from eva_agent.api.dependencies import get_settings, get_task_manager
from eva_agent.api.routes import router
from eva_agent.config.settings import Settings
from eva_agent.task.manager import TaskManager
from eva_agent.task.models import (
    ExpResult,
    SSHCheck,
    Task,
    TaskResult,
    TaskStatus,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def project_root() -> str:
    """Return the absolute path to the project root directory."""
    return os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..")
    )


@pytest.fixture(scope="session")
def rules_dir(project_root: str) -> str:
    """Return the absolute path to the config/rules directory."""
    return os.path.join(project_root, "config", "rules")


# ---------------------------------------------------------------------------
# Core domain object fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_settings() -> Settings:
    """Create Settings with test values."""
    return Settings(
        host="127.0.0.1",
        port=9999,
        upload_dir="/tmp/test_eva_uploads",
        task_timeout=10,
        docker_image="test-image:latest",
        log_level="DEBUG",
    )


@pytest.fixture
def mock_task_manager(mock_settings: Settings) -> TaskManager:
    """Create a TaskManager with mock_settings (no background worker started)."""
    return TaskManager(settings=mock_settings)


@pytest.fixture
def mock_exp_result() -> ExpResult:
    """Return a sample ExpResult."""
    return ExpResult(
        stdout="test output",
        stderr="",
        exit_code=0,
        duration=1.5,
    )


@pytest.fixture
def mock_ssh_checks() -> list[SSHCheck]:
    """Return a list of 3 SSHCheck objects (2 passed, 1 failed)."""
    return [
        SSHCheck(check_name="check_one", passed=True, details="Check one passed"),
        SSHCheck(check_name="check_two", passed=True, details="Check two passed"),
        SSHCheck(check_name="check_three", passed=False, details="Check three failed"),
    ]


@pytest.fixture
def mock_evidence() -> list[dict]:
    """Return a list of evidence dicts with exp_execution and ssh_verification items."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "type": "exp_execution",
            "source": "sandbox",
            "data": {
                "stdout": "exploit succeeded",
                "stderr": "",
                "exit_code": 0,
                "duration": 1.5,
            },
            "timestamp": now,
        },
        {
            "type": "ssh_verification",
            "source": "ssh",
            "data": {
                "check_name": "check_one",
                "passed": True,
                "details": "Check one passed",
            },
            "timestamp": now,
        },
        {
            "type": "ssh_verification",
            "source": "ssh",
            "data": {
                "check_name": "check_two",
                "passed": True,
                "details": "Check two passed",
            },
            "timestamp": now,
        },
        {
            "type": "metadata",
            "source": "request",
            "data": {
                "verify_type": "rce",
                "target_ip": "192.168.1.100",
                "target_port": 22,
                "execute_cmd": "python exploit.py",
            },
            "timestamp": now,
        },
    ]


@pytest.fixture
def mock_task() -> Task:
    """Return a Task with test data (verify_type='rce')."""
    task_request = {
        "execute_cmd": "python exploit.py",
        "target_ip": "192.168.1.100",
        "target_port": 22,
        "verify_type": "rce",
        "ssh_user": "root",
    }
    return Task(
        id="test-task-id-12345",
        request=task_request,
        file_path="/tmp/test_eva_uploads/test-task-id-12345/exploit",
        status=TaskStatus.PENDING,
    )


# ---------------------------------------------------------------------------
# FastAPI TestClient fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def client(mock_settings: Settings, mock_task_manager: TaskManager) -> TestClient:
    """Create a TestClient with mocked Settings and TaskManager dependencies."""
    app = FastAPI()
    app.include_router(router)

    app.dependency_overrides[get_settings] = lambda: mock_settings
    app.dependency_overrides[get_task_manager] = lambda: mock_task_manager

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# pytest-asyncio configuration
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest-asyncio so that ``@pytest.mark.asyncio``
    marked tests run correctly alongside synchronous tests."""
    config.option.asyncio_mode = "strict"
    # Suppress the deprecation warning about missing loop_scope;
    # function-scoped loops match the existing synchronous fixtures.
    config.option.asyncio_default_fixture_loop_scope = "function"
