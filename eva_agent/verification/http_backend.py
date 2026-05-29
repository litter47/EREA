"""HTTP-only verification backend.

For targets where no shell access is available (no SSH, no Docker exec,
no WinRM).  Verification is limited to HTTP-based checks such as status
code analysis, content inspection, and header analysis.
"""

from __future__ import annotations

import logging
from typing import Any

from eva_agent.verification.backend import VerificationBackend

logger = logging.getLogger(__name__)


class HTTPBackend(VerificationBackend):
    """Verification backend that verifies exploit success through
    HTTP requests only.

    This backend is useful when the target exposes nothing but an HTTP
    service (web applications, APIs).  It cannot run shell commands,
    so RCE/priv_esc verifiers will work in a degraded mode.
    """

    def __init__(self) -> None:
        pass

    @property
    def backend_type(self) -> str:
        return "http"

    async def connect(self, target: dict) -> Any:
        """No persistent connection needed; returns target config dict.

        Expects target dict keys: host (target IP), port (target port).
        """
        host: str = target.get("host", "")
        port: int = int(target.get("port", 80))
        if not host:
            raise ValueError("HTTPBackend: 'host' is required.")

        session = {
            "host": host,
            "port": port,
            "base_url": f"http://{host}:{port}",
        }
        logger.info(
            "HTTPBackend configured for %s", session["base_url"]
        )
        return session

    async def run(
        self,
        session: Any,
        cmd: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Execute an HTTP-based check.

        *session* is the dict returned by connect().
        *cmd* is interpreted as an HTTP path or full URL to check.

        For simple checks we spawn an httpx GET and return status +
        body summary.
        """
        import httpx

        base_url = session.get("base_url", "")
        # cmd can be a path like "/admin" or a full URL
        url = cmd if cmd.startswith("http") else f"{base_url}{cmd}"

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url, follow_redirects=True)
                body = resp.text[:2000]  # truncate
                stdout = (
                    f"HTTP {resp.status_code}\n"
                    f"Content-Type: {resp.headers.get('content-type', 'N/A')}\n"
                    f"Content-Length: {len(resp.content)}\n"
                    f"\n{body}"
                )
                return stdout, "", 0 if resp.status_code == 200 else 1
        except httpx.TimeoutException:
            return "", f"Timeout accessing {url}", -1
        except Exception as exc:
            return "", str(exc), -1

    async def disconnect(self, session: Any) -> None:
        """No persistent connection to close."""
        pass
