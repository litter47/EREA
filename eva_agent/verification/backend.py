"""Abstract base class for pluggable verification backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from eva_agent.task.models import SSHCheck


class VerificationBackend(ABC):
    """Abstract base for all verification backends.

    Each backend represents a different way to reach the target and
    execute verification commands: SSH, Docker exec, WinRM, HTTP, etc.
    """

    @abstractmethod
    async def connect(self, target: dict) -> Any:
        """Establish a connection/session to the target.

        Args:
            target: Dictionary of connection parameters (host, port,
                credentials, container_name, etc. - varies by backend).

        Returns:
            A session/connection object specific to the backend.
        """
        ...

    @abstractmethod
    async def run(
        self,
        session: Any,
        cmd: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Execute a command on the target via the active session.

        Args:
            session: Active session object returned by connect().
            cmd: Shell command to execute.
            timeout: Timeout in seconds.

        Returns:
            Tuple of (stdout, stderr, exit_code).
        """
        ...

    @abstractmethod
    async def disconnect(self, session: Any) -> None:
        """Close an active session/connection.

        Args:
            session: Active session object to close.
        """
        ...

    # ------------------------------------------------------------------
    # Shared verify() logic -- dispatches to type-specific verifiers.
    # All backends use the same verifier modules; the only difference is
    # how connect/run/disconnect work.
    # ------------------------------------------------------------------

    async def verify(
        self,
        session: Any,
        verify_type: str,
        evidence: dict | None = None,
    ) -> list[SSHCheck]:
        """Perform structured verification checks against the target.

        Dispatches to the appropriate verifier module based on
        *verify_type*:

        - "rce"          : remote code execution checks
        - "info_leak"    : information leakage checks
        - "priv_esc"     : privilege escalation checks
        - "auth_bypass"  : authentication bypass checks

        Args:
            session: Active session from connect().
            verify_type: One of "rce", "info_leak", "priv_esc",
                "auth_bypass".
            evidence: Optional contextual info (target IP/port etc.).

        Returns:
            List of SSHCheck results.

        Raises:
            ValueError: If verify_type is not recognised.
        """
        evidence = evidence or {}

        if verify_type == "rce":
            from eva_agent.ssh.verifiers.rce import verify as rce_verify

            return await rce_verify(self, session, evidence)
        elif verify_type == "info_leak":
            from eva_agent.ssh.verifiers.info_leak import (
                verify as info_leak_verify,
            )

            return await info_leak_verify(self, session, evidence)
        elif verify_type == "priv_esc":
            from eva_agent.ssh.verifiers.priv_esc import (
                verify as priv_esc_verify,
            )

            return await priv_esc_verify(self, session, evidence)
        elif verify_type == "auth_bypass":
            from eva_agent.ssh.verifiers.auth_bypass import (
                verify as auth_bypass_verify,
            )

            return await auth_bypass_verify(self, session, evidence)
        else:
            raise ValueError(
                f"Unknown verify_type: '{verify_type}'. "
                f"Expected one of: rce, info_leak, priv_esc, auth_bypass."
            )

    @property
    @abstractmethod
    def backend_type(self) -> str:
        """Human-readable identifier for this backend type."""
        ...
