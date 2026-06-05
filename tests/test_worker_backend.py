"""Tests for ExecutionWorker multi-backend routing."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from eva_agent.config.settings import Settings
from eva_agent.task.models import ExpResult, Task, TaskResult, TaskStatus
from eva_agent.task.worker import ExecutionWorker


@pytest.fixture
def worker_settings() -> Settings:
    return Settings(
        host="127.0.0.1",
        port=9999,
        upload_dir="/tmp/test_eva_uploads",
        task_timeout=10,
        docker_image="test-image:latest",
        log_level="DEBUG",
    )


def _make_task(
    verify_backend: str = "ssh", container_name: str | None = None
) -> Task:
    request = {
        "execute_cmd": "python exp.py",
        "target_ip": "10.0.0.1",
        "target_port": 22,
        "verify_type": "rce",
        "verify_backend": verify_backend,
        "ssh_user": "root",
        "ssh_password": "test",
    }
    if container_name:
        request["container_name"] = container_name
    return Task(
        id="test-backend-task",
        request=request,
        file_path="/tmp/test/exploit",
        status=TaskStatus.PENDING,
    )


class TestWorkerBackendRouting:
    """Test that the worker selects the correct backend and handles errors."""

    @pytest.mark.asyncio
    async def test_worker_uses_ssh_backend(self, worker_settings: Settings) -> None:
        """Worker should use SSHBackend when verify_backend=ssh."""
        task = _make_task(verify_backend="ssh")

        with patch(
            "eva_agent.task.worker.SandboxExecutor"
        ) as MockExec, patch(
            "eva_agent.task.worker.get_backend"
        ) as mock_get_backend, patch(
            "eva_agent.task.worker.load_llm_config"
        ) as mock_llm_config, patch(
            "eva_agent.verification.factory._BACKEND_CLASSES", {}
        ):

            mock_llm_config.return_value = MagicMock(enabled=False)
            mock_exec = MockExec.return_value
            mock_exec.ensure_image = AsyncMock(return_value=True)
            from eva_agent.task.models import ExpResult

            mock_exec.execute = AsyncMock(
                return_value=ExpResult(
                    stdout="ok", stderr="", exit_code=0, duration=0.1
                )
            )

            mock_backend = AsyncMock()
            mock_backend.backend_type = "ssh"
            mock_backend.connect = AsyncMock(return_value="session")
            mock_backend.verify = AsyncMock(return_value=[])
            mock_backend.disconnect = AsyncMock(return_value=None)
            mock_get_backend.return_value = mock_backend

            worker = ExecutionWorker(worker_settings, config_dir="config")
            await worker.run(task)

            mock_get_backend.assert_called_once_with("ssh")
            mock_backend.connect.assert_called_once()
            mock_backend.verify.assert_called_once()
            mock_backend.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_worker_uses_docker_backend(
        self, worker_settings: Settings
    ) -> None:
        """Worker should use DockerExecBackend when verify_backend=docker."""
        task = _make_task(verify_backend="docker", container_name="target_ctr")

        with patch(
            "eva_agent.task.worker.SandboxExecutor"
        ) as MockExec, patch(
            "eva_agent.task.worker.get_backend"
        ) as mock_get_backend, patch(
            "eva_agent.task.worker.load_llm_config"
        ) as mock_llm_config, patch(
            "docker.from_env"
        ):

            mock_llm_config.return_value = MagicMock(enabled=False)
            mock_exec = MockExec.return_value
            mock_exec.ensure_image = AsyncMock(return_value=True)
            from eva_agent.task.models import ExpResult

            mock_exec.execute = AsyncMock(
                return_value=ExpResult(
                    stdout="ok", stderr="", exit_code=0, duration=0.1
                )
            )

            mock_backend = AsyncMock()
            mock_backend.backend_type = "docker"
            mock_backend.connect = AsyncMock(return_value="session")
            mock_backend.verify = AsyncMock(return_value=[])
            mock_backend.disconnect = AsyncMock(return_value=None)
            mock_get_backend.return_value = mock_backend

            worker = ExecutionWorker(worker_settings, config_dir="config")
            await worker.run(task)

            mock_get_backend.assert_called_once_with("docker")
            # Verify container_name was passed in target dict
            call_kwargs = mock_backend.connect.call_args[0][0]
            assert call_kwargs["container_name"] == "target_ctr"

    @pytest.mark.asyncio
    async def test_worker_handles_backend_connect_failure(
        self, worker_settings: Settings
    ) -> None:
        """Worker should handle backend connection failure gracefully."""
        task = _make_task(verify_backend="ssh")

        with patch(
            "eva_agent.task.worker.SandboxExecutor"
        ) as MockExec, patch(
            "eva_agent.task.worker.get_backend"
        ) as mock_get_backend, patch(
            "eva_agent.task.worker.load_llm_config"
        ) as mock_llm_config:

            mock_llm_config.return_value = MagicMock(enabled=False)
            mock_exec = MockExec.return_value
            mock_exec.ensure_image = AsyncMock(return_value=True)
            from eva_agent.task.models import ExpResult

            mock_exec.execute = AsyncMock(
                return_value=ExpResult(
                    stdout="ok", stderr="", exit_code=0, duration=0.1
                )
            )

            mock_backend = AsyncMock()
            mock_backend.backend_type = "ssh"
            mock_backend.connect = AsyncMock(
                side_effect=ConnectionError("SSH refused")
            )
            mock_backend.disconnect = AsyncMock(return_value=None)
            mock_get_backend.return_value = mock_backend

            worker = ExecutionWorker(worker_settings, config_dir="config")
            await worker.run(task)

            # Task should complete (not crash) even with connection failure
            assert task.status == TaskStatus.SUCCESS  # pipeline completed
            assert task.result is not None
            assert task.result.final_verdict == "FAIL"  # no evidence of success

    @pytest.mark.asyncio
    async def test_worker_handles_unknown_backend_fallback(
        self, worker_settings: Settings
    ) -> None:
        """Worker should fall back to SSH when backend type is unknown."""
        task = _make_task(verify_backend="nonexistent")

        with patch(
            "eva_agent.task.worker.SandboxExecutor"
        ) as MockExec, patch(
            "eva_agent.task.worker.get_backend"
        ) as mock_get_backend, patch(
            "eva_agent.task.worker.load_llm_config"
        ) as mock_llm_config:

            mock_llm_config.return_value = MagicMock(enabled=False)
            mock_exec = MockExec.return_value
            mock_exec.ensure_image = AsyncMock(return_value=True)
            from eva_agent.task.models import ExpResult

            mock_exec.execute = AsyncMock(
                return_value=ExpResult(
                    stdout="ok", stderr="", exit_code=0, duration=0.1
                )
            )

            mock_backend = AsyncMock()
            mock_backend.backend_type = "ssh"
            mock_backend.connect = AsyncMock(return_value="session")
            mock_backend.verify = AsyncMock(return_value=[])
            mock_backend.disconnect = AsyncMock(return_value=None)

            # First call raises, second returns SSH backend
            mock_get_backend.side_effect = [ValueError("Unknown"), mock_backend]

            worker = ExecutionWorker(worker_settings, config_dir="config")
            await worker.run(task)

            # Should have called get_backend twice: once for "nonexistent",
            # then fallback to "ssh"
            assert mock_get_backend.call_count == 2

    @pytest.mark.asyncio
    async def test_worker_uses_generated_rules_when_requested(
        self, worker_settings: Settings, tmp_path
    ) -> None:
        """LLM-generated rules are used instead of YAML verifier checks."""
        exploit_path = tmp_path / "exploit"
        exploit_path.write_text("int main(){return 0;}", encoding="utf-8")
        task = _make_task(verify_backend="ssh")
        task.file_path = str(exploit_path)
        task.request["execute_cmd"] = "auto"
        task.request["source_language"] = "c"
        task.request["generate_rules_with_llm"] = True

        generated_rules = {
            "logic": {"operator": "AND"},
            "checks": [
                {
                    "name": "marker_created",
                    "type": "file_exists",
                    "path": "/tmp/generated-marker",
                }
            ],
        }

        with patch(
            "eva_agent.task.worker.SandboxExecutor"
        ) as MockExec, patch(
            "eva_agent.task.worker.get_backend"
        ) as mock_get_backend, patch(
            "eva_agent.task.worker.load_llm_config"
        ) as mock_llm_config, patch(
            "eva_agent.task.worker.LLMClientFactory.create"
        ) as mock_create_llm:

            mock_llm_config.return_value = MagicMock(enabled=True)
            mock_llm = AsyncMock()
            mock_llm.generate_rules = AsyncMock(return_value=generated_rules)
            mock_llm.judge = AsyncMock(
                return_value=MagicMock(
                    success=False, confidence=0.0, reasoning=""
                )
            )
            mock_create_llm.return_value = mock_llm

            mock_exec = MockExec.return_value
            mock_exec.ensure_image = AsyncMock(return_value=True)
            mock_exec.execute = AsyncMock(
                return_value=ExpResult(
                    stdout="ok", stderr="", exit_code=0, duration=0.1
                )
            )

            mock_backend = AsyncMock()
            mock_backend.backend_type = "ssh"
            mock_backend.connect = AsyncMock(return_value="session")
            mock_backend.verify = AsyncMock(return_value=[])
            mock_backend.disconnect = AsyncMock(return_value=None)
            mock_backend.run = AsyncMock(return_value=("", "", 0))
            mock_get_backend.return_value = mock_backend

            worker = ExecutionWorker(worker_settings, config_dir="config")
            await worker.run(task)

            mock_exec.execute.assert_called_once_with(
                str(exploit_path),
                "auto",
                source_language="c",
            )
            mock_backend.verify.assert_not_called()
            mock_backend.run.assert_called_once()
            assert task.result is not None
            assert task.result.final_verdict == "SUCCESS"
            assert task.result.rule_score is not None
            assert task.result.rule_score.matched_rules == ["marker_created"]
