"""SSH verification backend using asyncssh."""

from __future__ import annotations

import logging
from typing import Any

import asyncssh

from eva_agent.verification.backend import VerificationBackend

logger = logging.getLogger(__name__)


class SSHBackend(VerificationBackend):
    """Verification backend that connects to targets over SSH.

    Supports password and private-key authentication.  This is the
    default backend and maintains backward compatibility with the
    original EVA-Agent architecture.
    """

    def __init__(self) -> None:
        pass

    @property
    def backend_type(self) -> str:
        return "ssh"

    async def connect(self, target: dict) -> Any:
        """Connect to target via SSH.

        Expects target dict keys: host, port (default 22), username
        (default "root"), and either password or ssh_key (content str)
        or client_keys (list of key file paths).
        """
        host: str = target.get("host", "")
        port: int = int(target.get("port", 22))
        username: str = target.get("username", "root")
        password: str | None = target.get("password")
        ssh_key: str | None = target.get("ssh_key")
        client_keys: list[str] | None = target.get("client_keys")

        if not host:
            raise ValueError("SSH target must include 'host'.")

        if password is not None:
            conn = await asyncssh.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                known_hosts=None,
            )
        elif client_keys is not None and len(client_keys) > 0:
            loaded_keys = [
                asyncssh.import_private_key(kp) for kp in client_keys
            ]
            conn = await asyncssh.connect(
                host=host,
                port=port,
                username=username,
                client_keys=loaded_keys,
                known_hosts=None,
            )
        elif ssh_key is not None:
            # ssh_key is raw content, write to temp file
            import tempfile
            import os as _os

            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".pem", delete=False
            )
            try:
                tmp.write(ssh_key)
                tmp.close()
                key = asyncssh.import_private_key(tmp.name)
                conn = await asyncssh.connect(
                    host=host,
                    port=port,
                    username=username,
                    client_keys=[key],
                    known_hosts=None,
                )
            finally:
                try:
                    _os.unlink(tmp.name)
                except Exception:
                    pass
        else:
            raise ValueError(
                "SSHBackend: provide 'password', 'ssh_key', or "
                "'client_keys'."
            )

        logger.info("SSH connected to %s:%d as %s", host, port, username)
        return conn

    async def run(
        self,
        session: Any,
        cmd: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Run a command over the SSH session."""
        result = await session.run(cmd, timeout=timeout)

        stdout = (
            result.stdout.decode("utf-8", errors="replace").strip()
            if isinstance(result.stdout, bytes)
            else str(result.stdout or "").strip()
        )
        stderr = (
            result.stderr.decode("utf-8", errors="replace").strip()
            if isinstance(result.stderr, bytes)
            else str(result.stderr or "").strip()
        )
        exit_code: int = (
            result.exit_code if result.exit_code is not None else -1
        )
        return stdout, stderr, exit_code

    async def disconnect(self, session: Any) -> None:
        """Close the SSH connection."""
        try:
            session.close()
        except Exception:
            logger.debug("Error closing SSH session", exc_info=True)
