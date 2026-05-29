"""SandboxExecutor for running exploits in an isolated Docker container.

Uses the docker Python SDK to manage container lifecycle and capture
command output, exit code, and execution duration.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Optional

import docker
from docker.errors import ContainerError, DockerException, ImageNotFound

from eva_agent.sandbox.image import ensure_runtime_image
from eva_agent.task.models import ExpResult


class SandboxExecutor:
    """Execute exploit commands inside a disposable Docker sandbox.

    The executor creates a temporary directory, copies the exploit file
    into it, runs the specified command inside a container mounted at that
    directory, collects stdout/stderr/exit-code/duration, and then cleans
    up.

    Attributes:
        image_name: The Docker image tag to use for sandbox containers.
        timeout: Maximum wall-clock seconds for command execution.
        _client: The docker.DockerClient instance.
        _image_ensured: Whether ensure_runtime_image() has been called.
    """

    def __init__(
        self,
        image_name: str = "eva-runtime:latest",
        timeout: int = 300,
    ) -> None:
        """Initialise the executor with a Docker client and image tag.

        Args:
            image_name: Tag of the Docker image to run containers from.
            timeout: Maximum execution time in seconds (default 300).
        """
        self.image_name: str = image_name
        self.timeout: int = timeout
        self._client: docker.DockerClient = docker.from_env()
        self._image_ensured: bool = False

    async def ensure_image(self) -> bool:
        """Ensure the runtime Docker image is available.

        Calls ensure_runtime_image() and caches the result so it is only
        attempted once per executor lifetime.

        Returns:
            True if the image is ready, False otherwise.
        """
        if self._image_ensured:
            return True

        loop = asyncio.get_running_loop()
        ready = await loop.run_in_executor(
            None,
            ensure_runtime_image,
            self._client,
            self.image_name,
        )
        self._image_ensured = ready
        return ready

    async def execute(
        self,
        exp_file_path: str,
        execute_cmd: str,
    ) -> ExpResult:
        """Execute a command inside the sandboxed Docker container.

        Copies the exploit file at *exp_file_path* into a temporary
        directory (as ``exploit``), then runs *execute_cmd* via
        ``sh -c`` inside the container.  Stdout, stderr, exit code, and
        wall-clock duration are captured and returned as an ExpResult.

        Args:
            exp_file_path: Absolute or relative path to the exploit file.
            execute_cmd: Shell command to run inside the container.

        Returns:
            An ExpResult containing the command output, exit code, and
            execution duration.  If any error occurs the exit code is -1
            and the error message is placed in stderr.
        """
        if not self._image_ensured:
            ready = await self.ensure_image()
            if not ready:
                return ExpResult(
                    stdout="",
                    stderr="Runtime image could not be prepared.",
                    exit_code=-1,
                    duration=0.0,
                )

        temp_dir: Optional[str] = None

        try:
            # Create a temporary directory for the exploit file
            temp_dir = tempfile.mkdtemp(prefix="eva_sandbox_")

            # Copy the exploit file into the temp directory as "exploit"
            src_path = Path(exp_file_path).resolve()
            if not src_path.is_file():
                return ExpResult(
                    stdout="",
                    stderr=f"Exploit file not found: {exp_file_path}",
                    exit_code=-1,
                    duration=0.0,
                )

            dest_path = Path(temp_dir) / "exploit"
            shutil.copy2(str(src_path), str(dest_path))
            os.chmod(str(dest_path), 0o755)

            # Build the docker run command
            container_image = self.image_name
            volume_bind = f"{temp_dir}:/exp"
            full_command = ["sh", "-c", execute_cmd]

            loop = asyncio.get_running_loop()
            start_time = time.monotonic()

            async def _run_container() -> ExpResult:
                def _do_run() -> tuple[str, str, int]:
                    """Synchronous docker SDK call."""
                    result = self._client.containers.run(
                        image=container_image,
                        command=full_command,
                        volumes={temp_dir: {"bind": "/exp", "mode": "rw"}},
                        working_dir="/exp",
                        mem_limit="512m",
                        nano_cpus=int(1 * 1e9),  # 1 CPU
                        security_opt=["no-new-privileges"],
                        network_mode="host",
                        remove=True,
                        stdout=True,
                        stderr=True,
                        detach=False,
                    )
                    if isinstance(result, bytes):
                        return result.decode("utf-8", errors="replace"), "", 0
                    # Container returned (output, logs) tuple
                    return str(result), "", 0

                try:
                    stdout_text, stderr_text, exit_code = await loop.run_in_executor(
                        None,
                        _do_run,
                    )
                except ContainerError as exc:
                    exit_code = exc.exit_status
                    stdout_text = (
                        exc.stderr.decode("utf-8", errors="replace")
                        if isinstance(exc.stderr, bytes)
                        else str(exc.stderr or "")
                    )
                    stderr_text = ""
                    # ContainerError may contain stdout as well
                    if exc.container:
                        try:
                            logs = exc.container.logs(stdout=True, stderr=False)
                            if logs:
                                stdout_text = logs.decode("utf-8", errors="replace")
                        except Exception:
                            pass
                except ImageNotFound as exc:
                    return ExpResult(
                        stdout="",
                        stderr=f"Docker image not found: {exc}",
                        exit_code=-1,
                        duration=0.0,
                    )
                except DockerException as exc:
                    return ExpResult(
                        stdout="",
                        stderr=f"Docker error: {exc}",
                        exit_code=-1,
                        duration=0.0,
                    )
                except Exception as exc:
                    return ExpResult(
                        stdout="",
                        stderr=f"Unexpected error: {exc}",
                        exit_code=-1,
                        duration=0.0,
                    )

                duration = time.monotonic() - start_time
                return ExpResult(
                    stdout=stdout_text.strip(),
                    stderr=stderr_text.strip(),
                    exit_code=exit_code,
                    duration=duration,
                )

            return await asyncio.wait_for(
                _run_container(),
                timeout=self.timeout,
            )

        except asyncio.TimeoutError:
            duration = self.timeout
            return ExpResult(
                stdout="",
                stderr=f"Command timed out after {self.timeout} seconds.",
                exit_code=-1,
                duration=float(duration),
            )
        except Exception as exc:
            return ExpResult(
                stdout="",
                stderr=f"Sandbox executor error: {exc}",
                exit_code=-1,
                duration=0.0,
            )
        finally:
            # Cleanup temporary directory
            if temp_dir is not None:
                await self._cleanup_temp_dir(temp_dir)

    async def _cleanup_temp_dir(self, path: str) -> None:
        """Remove a temporary directory recursively.

        Args:
            path: Filesystem path to the directory to remove.
        """
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, shutil.rmtree, path, True)
        except Exception:
            pass  # best-effort cleanup
