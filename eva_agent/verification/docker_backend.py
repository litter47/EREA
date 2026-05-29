"""Docker Exec verification backend.

Runs verification commands directly inside a Docker container via
``docker exec`` (through the Docker SDK).  No SSH or WinRM needed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from eva_agent.verification.backend import VerificationBackend

logger = logging.getLogger(__name__)


class DockerExecBackend(VerificationBackend):
    """Verification backend that uses ``docker exec`` to run commands
    directly inside a target container.

    This backend is ideal for Docker-based targets that do not have
    an SSH server running inside the container.
    """

    def __init__(self) -> None:
        import docker

        self._client = docker.from_env()

    @property
    def backend_type(self) -> str:
        return "docker"

    async def connect(self, target: dict) -> Any:
        """Look up the target container by name or ID.

        Expects target dict keys: container_name (str) -- the Docker
        container name or ID.

        Returns the Container object (which acts as a session).
        """
        container_name: str = target.get("container_name", "")
        if not container_name:
            raise ValueError(
                "DockerExecBackend: 'container_name' is required."
            )

        try:
            container = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: self._client.containers.get(container_name),
            )
        except Exception as exc:
            raise RuntimeError(
                f"Docker container '{container_name}' not found: {exc}"
            ) from exc

        logger.info(
            "DockerExecBackend attached to container '%s' (%s)",
            container_name,
            container.short_id,
        )
        return container

    async def run(
        self,
        session: Any,
        cmd: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Execute *cmd* inside the container.

        *session* is a docker.models.containers.Container object
        returned by ``connect()``.
        """
        container = session

        def _exec() -> tuple[str, str, int]:
            result = container.exec_run(
                cmd,
                stdout=True,
                stderr=True,
            )
            stdout = (
                result.output.decode("utf-8", errors="replace").strip()
                if result.output
                else ""
            )
            exit_code = (
                result.exit_code
                if result.exit_code is not None
                else -1
            )
            # Docker SDK doesn't separate stderr in exec_run by default
            return stdout, "", exit_code

        try:
            return await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, _exec),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Docker exec timed out after %ds: %s", timeout, cmd
            )
            return "", "TIMEOUT", -1

    async def disconnect(self, session: Any) -> None:
        """No-op -- container is not stopped, only detached."""
        pass
