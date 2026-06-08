"""Tests for the EVA-Agent HTTP API routes.

Uses FastAPI TestClient with dependency_overrides to inject mocked
Settings and TaskManager instances.
"""

from __future__ import annotations

from unittest.mock import mock_open, patch

from eva_agent.task.models import Task, TaskResult, TaskStatus


class TestSubmit:
    """Tests for POST /submit."""

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    @patch("uuid.uuid4", return_value="mocked-task-uuid-001")
    def test_submit_success(
        self, mock_uuid, mock_makedirs, mock_file, client, mock_task_manager
    ):
        """Submit a valid exploit with all required fields -> 202 + task_id."""
        response = client.post(
            "/submit",
            data={
                "execute_cmd": "python exploit.py",
                "target_ip": "192.168.1.100",
                "target_port": 22,
                "verify_type": "rce",
                "ssh_user": "root",
            },
            files={
                "exploit_file": (
                    "exploit.sh",
                    b"#!/bin/bash\necho pwned",
                    "text/plain",
                )
            },
        )

        assert response.status_code == 202
        data = response.json()
        assert data["task_id"] == "mocked-task-uuid-001"
        assert data["status"] == "PENDING"
        assert "accepted" in data["message"].lower()

        # Verify the task was submitted to the manager
        task = mock_task_manager.get("mocked-task-uuid-001")
        assert task is not None
        assert task.request["execute_cmd"] == "python exploit.py"
        assert task.request["target_ip"] == "192.168.1.100"
        assert task.request["target_port"] == 22
        assert task.request["verify_type"] == "rce"
        assert task.request["ssh_user"] == "root"
        assert task.request["generate_rules_with_llm"] is False

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    @patch("uuid.uuid4", return_value="mocked-task-uuid-c")
    def test_submit_c_source_detection(
        self, mock_uuid, mock_makedirs, mock_file, client, mock_task_manager
    ):
        """C/C++ uploads are marked for automatic source compilation."""
        response = client.post(
            "/submit",
            data={
                "execute_cmd": "auto",
                "target_ip": "192.168.1.100",
                "target_port": 22,
                "verify_type": "rce",
                "ssh_user": "root",
                "generate_rules_with_llm": "true",
            },
            files={
                "exploit_file": (
                    "exploit.c",
                    b"#include <stdio.h>\nint main(){puts(\"ok\");}",
                    "text/x-c",
                )
            },
        )

        assert response.status_code == 202
        task = mock_task_manager.get("mocked-task-uuid-c")
        assert task is not None
        assert task.request["source_language"] == "c"
        assert task.request["original_filename"] == "exploit.c"
        assert task.request["generate_rules_with_llm"] is True

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    @patch("uuid.uuid4", return_value="mocked-task-uuid-go")
    def test_submit_go_source_detection(
        self, mock_uuid, mock_makedirs, mock_file, client, mock_task_manager
    ):
        """Go uploads are marked for automatic source compilation."""
        response = client.post(
            "/submit",
            data={
                "execute_cmd": "auto",
                "target_ip": "192.168.1.100",
                "target_port": 22,
                "verify_type": "rce",
                "ssh_user": "root",
            },
            files={
                "exploit_file": (
                    "exploit.go",
                    b"package main\nfunc main() {}",
                    "text/x-go",
                )
            },
        )

        assert response.status_code == 202
        task = mock_task_manager.get("mocked-task-uuid-go")
        assert task is not None
        assert task.request["source_language"] == "go"
        assert task.request["original_filename"] == "exploit.go"

    def test_submit_missing_fields(self, client):
        """Submit without required fields -> 422 validation error."""
        response = client.post(
            "/submit",
            data={
                "execute_cmd": "python exploit.py",
                "target_ip": "192.168.1.100",
                # target_port, verify_type, ssh_user missing
            },
            files={
                "exploit_file": (
                    "exploit.sh",
                    b"#!/bin/bash\necho pwned",
                    "text/plain",
                )
            },
        )

        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

    def test_verify_type_invalid(self, client):
        """Submit with an invalid verify_type -> 422 validation error."""
        response = client.post(
            "/submit",
            data={
                "execute_cmd": "python exploit.py",
                "target_ip": "192.168.1.100",
                "target_port": 22,
                "verify_type": "invalid_type_xyz",
                "ssh_user": "root",
            },
            files={
                "exploit_file": (
                    "exploit.sh",
                    b"#!/bin/bash\necho pwned",
                    "text/plain",
                )
            },
        )

        assert response.status_code == 422
        data = response.json()
        assert "detail" in data


class TestGetTask:
    """Tests for GET /task/{id}."""

    def test_get_task(self, client, mock_task_manager, mock_task):
        """Retrieve an existing task -> 200 with task details."""
        mock_task_manager.submit(mock_task)

        response = client.get(f"/task/{mock_task.id}")
        assert response.status_code == 200

        data = response.json()
        assert data["task_id"] == mock_task.id
        assert data["status"] == mock_task.status.value
        assert "created_at" in data

    def test_get_task_not_found(self, client):
        """Retrieve a non-existent task -> 404."""
        response = client.get("/task/nonexistent-id")
        assert response.status_code == 404

        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"].lower()


class TestGetResult:
    """Tests for GET /result/{id}."""

    def test_get_result(self, client, mock_task_manager, mock_task):
        """Retrieve result for a completed task -> 200 with result dict."""
        task_result = TaskResult(
            exp_result=None,
            ssh_checks=[],
            evidence=[],
            rule_score=None,
            llm_judgment=None,
            final_verdict="SUCCESS",
            report_json={"key": "value"},
            report_md="# Report",
        )
        mock_task.result = task_result
        mock_task.status = TaskStatus.SUCCESS
        mock_task_manager.submit(mock_task)

        response = client.get(f"/result/{mock_task.id}")
        assert response.status_code == 200

        data = response.json()
        assert data["task_id"] == mock_task.id
        assert data["status"] == TaskStatus.SUCCESS.value
        assert data["result"] is not None
        assert data["result"]["final_verdict"] == "SUCCESS"
        assert data["result"]["report_json"] == {"key": "value"}

    def test_get_result_not_found(self, client):
        """Retrieve result for a non-existent task -> 404."""
        response = client.get("/result/nonexistent-id")
        assert response.status_code == 404

        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"].lower()

    def test_get_result_pending(self, client, mock_task_manager, mock_task):
        """Retrieve result for a task that is still running -> result is null."""
        # Task has no result set (still running)
        mock_task.status = TaskStatus.RUNNING
        mock_task.result = None
        mock_task_manager.submit(mock_task)

        response = client.get(f"/result/{mock_task.id}")
        assert response.status_code == 200

        data = response.json()
        assert data["task_id"] == mock_task.id
        assert data["status"] == TaskStatus.RUNNING.value
        assert data["result"] is None
