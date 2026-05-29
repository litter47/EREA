"""FastAPI dependency-injection helpers.

Provides singleton access to the global ``TaskManager`` and ``Settings``
instances so that route handlers and other components do not need to
manage lifecycle themselves.
"""

from __future__ import annotations

from eva_agent.config.settings import Settings
from eva_agent.task.manager import TaskManager

# ---------------------------------------------------------------------------
# Module-level singletons (initialised on first access)
# ---------------------------------------------------------------------------
_settings: Settings | None = None
_task_manager: TaskManager | None = None


def get_settings() -> Settings:
    """Return the global ``Settings`` singleton.

    The instance is created once and cached for the lifetime of the
    process.  Because ``Settings`` reads from environment variables
    there is no reason to reconstruct it per-request.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def get_task_manager() -> TaskManager:
    """Return the global ``TaskManager`` singleton.

    The manager is created once and its background worker loop is
    started automatically on first access.
    """
    global _task_manager
    if _task_manager is None:
        settings = get_settings()
        _task_manager = TaskManager(settings=settings)
    return _task_manager
