"""Tests for the TaskManager.

Verifies task submission, retrieval, listing, and the background worker
loop that processes tasks through the ExecutionWorker pipeline.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from eva_agent.task.manager import TaskManager
from eva_agent.task.models import Task, TaskResult, TaskStatus


class TestTaskManagerCore:
    """Tests for core TaskManager operations (no background worker)."""

    def test_submit_task(self, mock_task_manager: TaskManager):
        """Submit a task and verify it is stored and enqueued."""
        task = Task(id="submit-test-id", request={"cmd": "echo test"})

        returned_id = mock_task_manager.submit(task)

        assert returned_id == task.id
        # Task should be in the in-memory store
        assert mock_task_manager.get(task.id) is task
        # Task should be queued
        assert mock_task_manager._queue.qsize() == 1

    def test_get_task(self, mock_task_manager: TaskManager, mock_task: Task):
        """Submit a task then retrieve it by ID."""
        mock_task_manager.submit(mock_task)

        retrieved = mock_task_manager.get(mock_task.id)

        assert retrieved is mock_task
        assert retrieved.id == mock_task.id
        assert retrieved.request == mock_task.request

    def test_get_task_not_found(self, mock_task_manager: TaskManager):
        """Retrieve a non-existent task -> None."""
        result = mock_task_manager.get("does-not-exist")
        assert result is None

    def test_get_result(self, mock_task_manager: TaskManager, mock_task: Task):
        """Submit a task with a result, then retrieve the result by task ID."""
        task_result = TaskResult(
            exp_result=None,
            ssh_checks=[],
            evidence=[],
            rule_score=None,
            llm_judgment=None,
            final_verdict="SUCCESS",
        )
        mock_task.result = task_result
        mock_task_manager.submit(mock_task)

        retrieved = mock_task_manager.get_result(mock_task.id)

        assert retrieved is task_result
        assert retrieved.final_verdict == "SUCCESS"

    def test_list_tasks(self, mock_task_manager: TaskManager):
        """Submit 3 tasks and verify list_tasks returns all of them."""
        tasks = [
            Task(id="list-task-1"),
            Task(id="list-task-2"),
            Task(id="list-task-3"),
        ]
        for t in tasks:
            mock_task_manager.submit(t)

        all_tasks = mock_task_manager.list_tasks()

        assert len(all_tasks) == 3
        task_ids = {t.id for t in all_tasks}
        assert task_ids == {"list-task-1", "list-task-2", "list-task-3"}

    def test_get_result_none_when_no_task(self, mock_task_manager: TaskManager):
        """get_result returns None when task ID does not exist."""
        result = mock_task_manager.get_result("nonexistent")
        assert result is None

    def test_get_result_none_when_no_result(self, mock_task_manager: TaskManager, mock_task: Task):
        """get_result returns None when the task has no result yet."""
        mock_task.result = None
        mock_task_manager.submit(mock_task)

        result = mock_task_manager.get_result(mock_task.id)
        assert result is None

    def test_task_status_flow(self, mock_task: Task):
        """Task starts as PENDING."""
        assert mock_task.status == TaskStatus.PENDING


class TestTaskManagerWorker:
    """Tests for the background worker loop.

    These tests patch ExecutionWorker to avoid spinning up real Docker
    containers or SSH connections.
    """

    @pytest.mark.asyncio
    async def test_worker_processes_task(self, mock_task_manager: TaskManager):
        """Worker processes a task: status transitions PENDING->RUNNING->SUCCESS."""
        task = Task()

        async def mock_run(t: Task) -> None:
            """Simulate a successful ExecutionWorker.run()."""
            t.status = TaskStatus.SUCCESS

        with patch("eva_agent.task.worker.ExecutionWorker") as MockWorker:
            mock_worker_instance = MagicMock()
            mock_worker_instance.run = mock_run
            MockWorker.return_value = mock_worker_instance

            mock_task_manager.start()
            mock_task_manager.submit(task)

            # Give the event loop a chance to process the queue
            await asyncio.sleep(0.05)

            # The worker loop first sets RUNNING, then mock_run sets SUCCESS
            assert task.status == TaskStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_worker_handles_error(self, mock_task_manager: TaskManager):
        """When ExecutionWorker.run() raises, the task is marked FAILED."""
        task = Task()

        async def mock_run_raise(t: Task) -> None:
            raise RuntimeError("Simulated worker failure")

        with patch("eva_agent.task.worker.ExecutionWorker") as MockWorker:
            mock_worker_instance = MagicMock()
            mock_worker_instance.run = mock_run_raise
            MockWorker.return_value = mock_worker_instance

            mock_task_manager.start()
            mock_task_manager.submit(task)

            await asyncio.sleep(0.05)

            # The worker loop catches the exception and sets FAILED
            assert task.status == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self, mock_task_manager: TaskManager):
        """Calling start() multiple times is safe (no duplicate workers)."""
        with patch("eva_agent.task.worker.ExecutionWorker") as MockWorker:
            mock_worker_instance = MagicMock()
            mock_worker_instance.run = AsyncMock()
            MockWorker.return_value = mock_worker_instance

            mock_task_manager.start()
            mock_task_manager.start()  # second call should be a no-op
            mock_task_manager.start()  # third call should be a no-op

            # Submit a task and verify it still gets processed
            task = Task()

            async def mock_run(t: Task) -> None:
                t.status = TaskStatus.SUCCESS

            mock_worker_instance.run = mock_run
            mock_task_manager.submit(task)

            await asyncio.sleep(0.05)

            assert task.status == TaskStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_stop_cancels_worker(self, mock_task_manager: TaskManager):
        """Stopping the manager cancels the background worker."""
        with patch("eva_agent.task.worker.ExecutionWorker") as MockWorker:
            mock_worker_instance = MagicMock()
            mock_worker_instance.run = AsyncMock()
            MockWorker.return_value = mock_worker_instance

            mock_task_manager.start()
            assert mock_task_manager._worker_task is not None
            assert not mock_task_manager._worker_task.done()

            await mock_task_manager.stop()
            assert mock_task_manager._worker_task is None
