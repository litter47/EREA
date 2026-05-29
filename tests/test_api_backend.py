"""Tests for the multi-backend API fields in POST /submit."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from eva_agent.api.dependencies import get_settings, get_task_manager
from eva_agent.api.routes import router
from eva_agent.config.settings import Settings
from eva_agent.task.manager import TaskManager


def _make_client() -> tuple[TestClient, TaskManager]:
    """Build a TestClient with mocked dependencies."""
    settings = Settings(
        host="127.0.0.1", port=9999, upload_dir="/tmp/test_eva_uploads"
    )
    manager = TaskManager(settings=settings)
    manager.submit = MagicMock()  # Don't actually enqueue

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_task_manager] = lambda: manager
    return TestClient(app), manager


class TestBackendSubmitFields:
    """Test that the new backend-related fields are accepted."""

    def test_submit_defaults_to_ssh(self) -> None:
        client, manager = _make_client()
        with patch("os.makedirs"), patch(
            "uuid.uuid4", return_value="test-ssh-default"
        ), patch("builtins.open", MagicMock()):
            resp = client.post(
                "/submit",
                data={
                    "execute_cmd": "python exp.py",
                    "target_ip": "10.0.0.1",
                    "target_port": "22",
                    "verify_type": "rce",
                    "ssh_user": "root",
                    # verify_backend not provided -> defaults to ssh
                },
                files={
                    "exploit_file": (
                        "exp.py",
                        b"print('exploit')",
                        "text/x-python",
                    )
                },
            )
            assert resp.status_code == 202
            # Check that the task request has verify_backend = ssh
            call_args = manager.submit.call_args[0]
            task = call_args[0]
            assert task.request["verify_backend"] == "ssh"

    def test_submit_with_docker_backend(self) -> None:
        client, manager = _make_client()
        with patch("os.makedirs"), patch(
            "uuid.uuid4", return_value="test-docker"
        ), patch("builtins.open", MagicMock()):
            resp = client.post(
                "/submit",
                data={
                    "execute_cmd": "python exp.py",
                    "target_ip": "10.0.0.1",
                    "target_port": "80",
                    "verify_type": "rce",
                    "ssh_user": "root",
                    "verify_backend": "docker",
                    "container_name": "target_ctr",
                },
                files={
                    "exploit_file": (
                        "exp.py",
                        b"print('exploit')",
                        "text/x-python",
                    )
                },
            )
            assert resp.status_code == 202
            call_args = manager.submit.call_args[0]
            task = call_args[0]
            assert task.request["verify_backend"] == "docker"
            assert task.request["container_name"] == "target_ctr"

    def test_submit_with_winrm_backend(self) -> None:
        client, manager = _make_client()
        with patch("os.makedirs"), patch(
            "uuid.uuid4", return_value="test-winrm"
        ), patch("builtins.open", MagicMock()):
            resp = client.post(
                "/submit",
                data={
                    "execute_cmd": "python exp.py",
                    "target_ip": "10.0.0.1",
                    "target_port": "5986",
                    "verify_type": "priv_esc",
                    "ssh_user": "Administrator",
                    "ssh_password": "pass",
                    "verify_backend": "winrm",
                },
                files={
                    "exploit_file": (
                        "exp.py",
                        b"print('exploit')",
                        "text/x-python",
                    )
                },
            )
            assert resp.status_code == 202
            call_args = manager.submit.call_args[0]
            task = call_args[0]
            assert task.request["verify_backend"] == "winrm"

    def test_submit_with_http_backend(self) -> None:
        client, manager = _make_client()
        with patch("os.makedirs"), patch(
            "uuid.uuid4", return_value="test-http"
        ), patch("builtins.open", MagicMock()):
            resp = client.post(
                "/submit",
                data={
                    "execute_cmd": "python exp.py",
                    "target_ip": "10.0.0.1",
                    "target_port": "443",
                    "verify_type": "auth_bypass",
                    "ssh_user": "admin",
                    "verify_backend": "http",
                },
                files={
                    "exploit_file": (
                        "exp.py",
                        b"print('exploit')",
                        "text/x-python",
                    )
                },
            )
            assert resp.status_code == 202
            call_args = manager.submit.call_args[0]
            task = call_args[0]
            assert task.request["verify_backend"] == "http"

    def test_submit_invalid_backend_rejected(self) -> None:
        client, manager = _make_client()
        with patch("os.makedirs"), patch(
            "uuid.uuid4", return_value="test-invalid"
        ), patch("builtins.open", MagicMock()):
            resp = client.post(
                "/submit",
                data={
                    "execute_cmd": "python exp.py",
                    "target_ip": "10.0.0.1",
                    "target_port": "22",
                    "verify_type": "rce",
                    "ssh_user": "root",
                    "verify_backend": "invalid_backend",
                },
                files={
                    "exploit_file": (
                        "exp.py",
                        b"print('exploit')",
                        "text/x-python",
                    )
                },
            )
            assert resp.status_code == 422  # Validation error

    def test_submit_without_container_name_for_docker(self) -> None:
        """Docker backend without container_name should be accepted by API
        (the worker will handle the error)."""
        client, manager = _make_client()
        with patch("os.makedirs"), patch(
            "uuid.uuid4", return_value="test-no-ctr"
        ), patch("builtins.open", MagicMock()):
            resp = client.post(
                "/submit",
                data={
                    "execute_cmd": "python exp.py",
                    "target_ip": "10.0.0.1",
                    "target_port": "22",
                    "verify_type": "rce",
                    "ssh_user": "root",
                    "verify_backend": "docker",
                    # container_name not provided
                },
                files={
                    "exploit_file": (
                        "exp.py",
                        b"print('exploit')",
                        "text/x-python",
                    )
                },
            )
            assert resp.status_code == 202
