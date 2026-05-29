"""WinRM verification backend for Windows targets.

Uses the ``pywinrm`` library (if installed) to execute commands on
Windows machines that expose WinRM instead of SSH.
"""

from __future__ import annotations

import logging
from typing import Any

from eva_agent.verification.backend import VerificationBackend

logger = logging.getLogger(__name__)


class WinRMBackend(VerificationBackend):
    """Verification backend that connects to Windows targets over WinRM.

    Requires the ``pywinrm`` package to be installed.  If the package
    is missing, ``connect()`` raises an ``ImportError`` with a clear
    message.
    """

    def __init__(self) -> None:
        self._check_deps()

    @staticmethod
    def _check_deps() -> None:
        try:
            import winrm  # noqa: F401
        except ImportError:
            raise ImportError(
                "WinRMBackend requires 'pywinrm'.  Install it with: "
                "pip install pywinrm"
            )

    @property
    def backend_type(self) -> str:
        return "winrm"

    async def connect(self, target: dict) -> Any:
        """Create a WinRM session.

        Expects target dict keys:
            host (str), port (int, default 5986), username (str),
            password (str).
        Optional: transport (str, default "ntlm"), ssl (bool, default True),
        cert_validation (str, default "ignore").
        """
        import winrm

        host: str = target.get("host", "")
        if not host:
            raise ValueError("WinRMBackend: 'host' is required.")

        port: int = int(target.get("port", 5986))
        username: str = target.get("username", "Administrator")
        password: str = target.get("password", "")
        transport: str = target.get("transport", "ntlm")
        ssl: bool = target.get("ssl", True)
        cert_validation: str = target.get("cert_validation", "ignore")

        protocol = "https" if ssl else "http"
        endpoint = f"{protocol}://{host}:{port}/wsman"

        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport=transport,
            server_cert_validation=cert_validation,
        )

        logger.info(
            "WinRM connected to %s (transport=%s)", endpoint, transport
        )
        return session

    async def run(
        self,
        session: Any,
        cmd: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Execute a command over WinRM.

        *session* is a ``winrm.Session`` object.
        """
        try:
            # Wrap shell command for Windows
            # If it looks like a Linux command, translate basic idioms
            windows_cmd = self._translate_cmd(cmd)
            result = session.run_cmd(windows_cmd)
            stdout = (
                result.std_out.decode("utf-8", errors="replace").strip()
            )
            stderr = (
                result.std_err.decode("utf-8", errors="replace").strip()
            )
            exit_code = result.status_code
            return stdout, stderr, exit_code
        except Exception as exc:
            logger.warning("WinRM command failed: %s -- %s", cmd, exc)
            return "", str(exc), -1

    async def disconnect(self, session: Any) -> None:
        """No persistent connection to close with WinRM."""
        pass

    @staticmethod
    def _translate_cmd(cmd: str) -> str:
        """Translate common *nix commands to Windows equivalents.

        This is a best-effort translation layer for verification
        commands that the verifier modules may issue.
        """
        translations = {
            "test -f ": "if exist ",
            "cat ": "type ",
            "whoami": "whoami",
            "id": "whoami /all",
            "sudo -l": "net user %USERNAME%",
            "sudo -n true": "net session >nul 2>&1",
            "ps aux": "tasklist",
            "ps -U root": "tasklist /V",
            "ss -tlnp": "netstat -an",
            "find /tmp -type f -mmin -5": "dir /s /b C:\\Temp",
            "/tmp/pwned": "C:\\Temp\\pwned",
            "/etc/shadow": "C:\\Windows\\System32\\config\\SAM",
            "/etc/passwd": "C:\\Windows\\System32\\config\\SAM",
        }

        translated = cmd
        for nix, win in translations.items():
            translated = translated.replace(nix, win)
        return translated
