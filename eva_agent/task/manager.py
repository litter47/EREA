"""In-memory task queue and lifecycle manager.

The ``TaskManager`` holds all submitted tasks in a thread-safe dictionary,
maintains an ``asyncio.Queue`` for pending work, and runs a background
worker coroutine that dispatches tasks to the sandbox ``ExecutionWorker``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from eva_agent.config.settings import Settings
from eva_agent.task.models import Task, TaskResult, TaskStatus

logger = logging.getLogger(__name__)


class TaskManager:
    """Manages the lifecycle of exploit-verification tasks.

    Responsible for:
    * Accepting new task submissions.
    * Storing tasks by ID for later retrieval.
    * Feeding tasks into an async queue consumed by a background worker.
    * Starting / stopping the background worker loop.

    Thread-safety is guaranteed by using ``asyncio.Lock`` for the
    in-memory store and an ``asyncio.Queue`` for the work pipeline.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._tasks: dict[str, Task] = {}
        self._queue: asyncio.Queue[Task] = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task[None]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(self, task: Task) -> str:
        """Register *task* and enqueue it for execution.

        Returns the task's unique ID (``task.id``).
        """
        self._tasks[task.id] = task
        self._queue.put_nowait(task)
        logger.info("Task %s submitted and enqueued.", task.id)
        return task.id

    def get(self, task_id: str) -> Optional[Task]:
        """Look up a task by its ID, returning ``None`` if unknown."""
        return self._tasks.get(task_id)

    def get_result(self, task_id: str) -> Optional[TaskResult]:
        """Return the result for *task_id*, or ``None``."""
        task = self._tasks.get(task_id)
        return task.result if task is not None else None

    def list_tasks(self) -> list[Task]:
        """Return a shallow copy of all known tasks."""
        return list(self._tasks.values())

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Create and schedule the background worker loop.

        Safe to call multiple times -- subsequent calls are no-ops.
        The worker is started as an asyncio Task so it integrates
        with any running event loop.
        """
        if self._worker_task is not None:
            logger.debug("Worker already running; ignoring duplicate start.")
            return

        loop = asyncio.get_event_loop()
        self._worker_task = loop.create_task(self._worker_loop())
        logger.info("TaskManager background worker started.")

    async def stop(self) -> None:
        """Cancel the background worker and wait for it to finish."""
        if self._worker_task is None:
            return

        self._worker_task.cancel()
        try:
            await self._worker_task
        except asyncio.CancelledError:
            logger.info("TaskManager background worker cancelled.")
        self._worker_task = None

    # ------------------------------------------------------------------
    # Internal worker
    # ------------------------------------------------------------------

    async def _worker_loop(self) -> None:
        """Continuously pull tasks from the queue and execute them.

        One task is processed at a time.  If the ``ExecutionWorker``
        raises an exception the task is marked as ``FAILED`` and the
        error is logged so subsequent tasks are not blocked.
        """
        # Lazy import -- the ExecutionWorker may live in a separate
        # module that is not yet loaded at import time, keeping the
        # dependency chain clean.
        from eva_agent.task.worker import ExecutionWorker

        worker = ExecutionWorker(settings=self._settings)

        logger.info("Worker loop started; waiting for tasks ...")
        while True:
            try:
                task = await self._queue.get()
            except asyncio.CancelledError:
                logger.info("Worker loop received cancellation.")
                break

            try:
                await self._update_status(task, TaskStatus.RUNNING)
                await worker.run(task)
            except Exception:
                logger.exception(
                    "Task %s failed with an unexpected error.", task.id
                )
                await self._update_status(task, TaskStatus.FAILED)
            finally:
                self._queue.task_done()

        logger.info("Worker loop exited.")

    async def _update_status(
        self, task: Task, status: TaskStatus
    ) -> None:
        """Atomically update *task*'s status and timestamp."""
        from datetime import datetime, timezone

        task.status = status
        task.updated_at = datetime.now(timezone.utc)
