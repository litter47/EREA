"""FastAPI application entry-point for EVA-Agent.

The EVA (Exploit Verification Agent) platform provides an HTTP API for
submitting exploit binaries / scripts, executing them in isolated Docker
sandboxes, verifying results over SSH, evaluating against rule sets,
and optionally obtaining LLM-based judgment.

Start the server with::

    uvicorn eva_agent.main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import docker
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from eva_agent.api.dependencies import get_settings, get_task_manager
from eva_agent.api.routes import router
from eva_agent.config.settings import Settings
from eva_agent.sandbox.image import ensure_runtime_image
from eva_agent.task.manager import TaskManager

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Lifespan context manager
# ------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage the application lifecycle.

    Startup
        - Resolve application settings.
        - Ensure the runtime Docker image is built / available.
        - Initialise and start the ``TaskManager`` background worker.

    Shutdown
        - Gracefully stop the ``TaskManager`` background worker.
    """
    settings: Settings = get_settings()

    # ---- Startup -------------------------------------------------------
    logger.info(
        "Starting EVA-Agent (log_level=%s, task_timeout=%d, "
        "docker_image=%s)",
        settings.log_level,
        settings.task_timeout,
        settings.docker_image,
    )

    # Ensure the runtime Docker image is available.
    logger.info("Ensuring runtime Docker image '%s' ...", settings.docker_image)
    try:
        loop = asyncio.get_running_loop()
        client = docker.from_env()
        image_ready = await loop.run_in_executor(
            None,
            ensure_runtime_image,
            client,
            settings.docker_image,
        )
        if image_ready:
            logger.info("Runtime Docker image is ready.")
        else:
            logger.warning(
                "Runtime Docker image could not be prepared; "
                "tasks may fail if the image is missing."
            )
    except Exception:
        logger.exception(
            "Failed to ensure runtime Docker image during startup."
        )

    # Start the background task worker.
    task_manager: TaskManager = get_task_manager()
    task_manager.start()
    logger.info("TaskManager background worker started.")

    yield  # Application runs here.

    # ---- Shutdown ------------------------------------------------------
    logger.info("Shutting down EVA-Agent ...")
    await task_manager.stop()
    logger.info("TaskManager background worker stopped.")


# ------------------------------------------------------------------
# FastAPI application instance
# ------------------------------------------------------------------

app = FastAPI(
    title="EVA-Agent",
    description="Exploit Verification Agent Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# -- Logging --------------------------------------------------------
settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# -- CORS middleware (allow all origins for local development) -------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- API routes -----------------------------------------------------
app.include_router(router)


# ------------------------------------------------------------------
# Direct execution
# ------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "eva_agent.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
    )
