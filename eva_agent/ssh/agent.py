"""SSH verification agent for remote exploit validation.

Provides high-level async methods to connect to a target host over SSH,
run commands, and delegate verification checks to type-specific verifier
modules.
"""

from __future__ import annotations

from typing import Optional

import asyncssh
from asyncssh import SSHClientConnection

from eva_agent.task.models import SSHCheck


class SSHVerificationAgent:
    """SSH-based verification agent.

    Handles SSH connection lifecycle (password or key-based auth),
    remote command execution, and dispatches structured checks to
    specialised verifier modules based on the exploit type.
    """

    def __init__(self) -> None:
        """Initialise the agent."""
        pass

    async def connect(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        client_keys: Optional[list[str]] = None,
    ) -> SSHClientConnection:
        """Establish an SSH connection to the target host.

        Args:
            host: Target hostname or IP address.
            port: SSH port (default 22).
            username: Remote username (default "root").
            password: Password for password-based authentication.
            client_keys: List of paths to private key files for key-based
                authentication.

        Returns:
            An active SSHClientConnection instance.

        Raises:
            asyncssh.Error: If the connection or authentication fails.
            ValueError: If neither password nor client_keys are provided.
        """
        if password is not None:
            conn = await asyncssh.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                known_hosts=None,
            )
        elif client_keys is not None and len(client_keys) > 0:
            loaded_keys = []
            for key_path in client_keys:
                key = asyncssh.import_private_key(key_path)
                loaded_keys.append(key)
            conn = await asyncssh.connect(
                host=host,
                port=port,
                username=username,
                client_keys=loaded_keys,
                known_hosts=None,
            )
        else:
            raise ValueError(
                "Either 'password' or 'client_keys' must be provided."
            )

        return conn

    async def run(
        self,
        conn: SSHClientConnection,
        cmd: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Run a shell command on the remote host and return its output.

        Args:
            conn: An active SSHClientConnection.
            cmd: The shell command to execute.
            timeout: Maximum time in seconds to wait for the command to
                complete (default 30).

        Returns:
            A tuple of (stdout, stderr, exit_code).  Both stdout and
            stderr are decoded strings with leading/trailing whitespace
            stripped.

        Raises:
            asyncio.TimeoutError: If the command exceeds *timeout*.
            asyncssh.Error: If the command could not be executed.
        """
        result = await conn.run(cmd, timeout=timeout)

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
        exit_code: int = result.exit_code if result.exit_code is not None else -1

        return stdout, stderr, exit_code

    async def verify(
        self,
        conn: SSHClientConnection,
        verify_type: str,
        evidence: Optional[dict] = None,
    ) -> list[SSHCheck]:
        """Perform structured verification checks against the remote host.

        Dispatches to the appropriate verifier module based on
        *verify_type*:

        - ``"rce"``          : remote code execution checks
        - ``"info_leak"``    : information leakage checks
        - ``"priv_esc"``     : privilege escalation checks
        - ``"auth_bypass"``  : authentication bypass checks

        Args:
            conn: An active SSHClientConnection.
            verify_type: One of ``"rce"``, ``"info_leak"``,
                ``"priv_esc"``, or ``"auth_bypass"``.
            evidence: Optional dictionary containing contextual
                information (e.g. target IP/port for auth bypass).

        Returns:
            A list of SSHCheck results, one per check performed.

        Raises:
            ValueError: If *verify_type* is not recognised.
        """
        evidence = evidence or {}

        if verify_type == "rce":
            from eva_agent.ssh.verifiers.rce import verify as rce_verify

            return await rce_verify(self, conn, evidence)
        elif verify_type == "info_leak":
            from eva_agent.ssh.verifiers.info_leak import (
                verify as info_leak_verify,
            )

            return await info_leak_verify(self, conn, evidence)
        elif verify_type == "priv_esc":
            from eva_agent.ssh.verifiers.priv_esc import (
                verify as priv_esc_verify,
            )

            return await priv_esc_verify(self, conn, evidence)
        elif verify_type == "auth_bypass":
            from eva_agent.ssh.verifiers.auth_bypass import (
                verify as auth_bypass_verify,
            )

            return await auth_bypass_verify(self, conn, evidence)
        else:
            raise ValueError(
                f"Unknown verify_type: '{verify_type}'. "
                f"Expected one of: rce, info_leak, priv_esc, auth_bypass."
            )
