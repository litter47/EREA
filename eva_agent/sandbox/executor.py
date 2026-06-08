"""SandboxExecutor for running exploits in an isolated Docker container.

Uses the docker Python SDK to manage container lifecycle and capture
command output, exit code, and execution duration.
"""

from __future__ import annotations

import asyncio
import io
import tarfile
import time
from pathlib import Path

import docker
from docker.errors import DockerException, ImageNotFound

from eva_agent.sandbox.image import ensure_runtime_image
from eva_agent.task.models import ExpResult


class SandboxExecutor:
    """Execute exploit commands inside a disposable Docker sandbox.

    The executor creates a disposable container, copies the exploit file
    into it, runs the specified command, collects stdout/stderr/exit-code
    and duration, and then cleans up.

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
        source_language: str | None = None,
    ) -> ExpResult:
        """Execute a command inside the sandboxed Docker container.

        Copies the exploit file at *exp_file_path* into the container as
        ``/exp/exploit``, then runs *execute_cmd* via ``sh -c`` inside
        the container. Stdout, stderr, exit code, and wall-clock duration
        are captured and returned as an ExpResult.

        Args:
            exp_file_path: Absolute or relative path to the exploit file.
            execute_cmd: Shell command to run inside the container.
            source_language: Optional source language hint. ``"c"`` and
                ``"cpp"`` trigger an in-container build step before run.

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

        try:
            src_path = Path(exp_file_path).resolve()
            if not src_path.is_file():
                return ExpResult(
                    stdout="",
                    stderr=f"Exploit file not found: {exp_file_path}",
                    exit_code=-1,
                    duration=0.0,
                )

            container_image = self.image_name
            build_cmd = self._build_command(source_language)
            run_command = self._run_command(execute_cmd, source_language)
            full_command = ["sh", "-c", run_command]

            loop = asyncio.get_running_loop()
            start_time = time.monotonic()

            async def _run_container() -> ExpResult:
                def _do_run() -> tuple[str, str, int]:
                    """Synchronous docker SDK call."""
                    container = None
                    try:
                        container = self._client.containers.create(
                            image=container_image,
                            command=["sleep", str(self.timeout + 5)],
                            working_dir="/exp",
                            mem_limit="512m",
                            nano_cpus=int(1 * 1e9),  # 1 CPU
                            security_opt=["no-new-privileges"],
                            network_mode="host",
                        )
                        container.start()
                        container.exec_run("mkdir -p /exp")
                        container.put_archive(
                            "/exp",
                            self._build_exploit_archive(src_path),
                        )
                        container.exec_run("chmod 755 /exp/exploit")
                        if build_cmd is not None:
                            build_result = container.exec_run(
                                ["sh", "-c", build_cmd],
                                stdout=True,
                                stderr=True,
                            )
                            build_output = self._decode_exec_output(
                                build_result.output
                            )
                            build_exit = (
                                build_result.exit_code
                                if build_result.exit_code is not None
                                else -1
                            )
                            if build_exit != 0:
                                return (
                                    build_output,
                                    (
                                        "Build failed for "
                                        f"{source_language or 'source'} source."
                                    ),
                                    build_exit,
                                )
                            container.exec_run("chmod 755 /exp/exploit_bin")
                        result = container.exec_run(
                            full_command,
                            stdout=True,
                            stderr=True,
                        )
                        output = self._decode_exec_output(result.output)
                        exit_code = (
                            result.exit_code
                            if result.exit_code is not None
                            else -1
                        )
                        return output, "", exit_code
                    finally:
                        if container is not None:
                            try:
                                container.remove(force=True)
                            except Exception:
                                pass

                try:
                    stdout_text, stderr_text, exit_code = await loop.run_in_executor(
                        None,
                        _do_run,
                    )
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

    @staticmethod
    def _build_exploit_archive(src_path: Path) -> bytes:
        """Create a tar archive suitable for Docker put_archive()."""
        data = src_path.read_bytes()
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name="exploit")
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
        tar_stream.seek(0)
        return tar_stream.getvalue()

    @staticmethod
    def _build_command(source_language: str | None) -> str | None:
        """Return the compile command for source uploads, if needed."""
        language = (source_language or "").lower()
        if language == "c":
            return "gcc -x c /exp/exploit -o /exp/exploit_bin"
        if language in {"cpp", "c++"}:
            return "g++ -x c++ /exp/exploit -o /exp/exploit_bin"
        if language == "go":
            return (
                "cp /exp/exploit /exp/exploit.go && "
                "go build -o /exp/exploit_bin /exp/exploit.go"
            )
        return None

    @staticmethod
    def _run_command(execute_cmd: str, source_language: str | None) -> str:
        """Choose the runtime command after optional source compilation."""
        command = (execute_cmd or "").strip()
        if (source_language or "").lower() in {"c", "cpp", "c++", "go"} and (
            not command or command.lower() == "auto"
        ):
            return "/exp/exploit_bin"
        return command

    @staticmethod
    def _decode_exec_output(output: bytes | str | None) -> str:
        if output is None:
            return ""
        if isinstance(output, bytes):
            return output.decode("utf-8", errors="replace")
        return str(output)
