"""Factory that creates the correct VerificationBackend for a given type."""

from __future__ import annotations

import logging

from eva_agent.verification.backend import VerificationBackend

logger = logging.getLogger(__name__)

# Cache of backend-type -> class mapping
_BACKEND_CLASSES: dict[str, type[VerificationBackend]] = {}


def _ensure_registered() -> None:
    """Lazy-register all built-in backends."""
    if _BACKEND_CLASSES:
        return

    from eva_agent.verification.ssh_backend import SSHBackend
    from eva_agent.verification.docker_backend import DockerExecBackend

    _BACKEND_CLASSES["ssh"] = SSHBackend
    _BACKEND_CLASSES["docker"] = DockerExecBackend

    # Optional backends -- only register if their dependencies are
    # available.

    try:
        from eva_agent.verification.http_backend import HTTPBackend

        _BACKEND_CLASSES["http"] = HTTPBackend
    except ImportError:
        logger.debug("HTTPBackend not available")

    try:
        from eva_agent.verification.winrm_backend import WinRMBackend

        _BACKEND_CLASSES["winrm"] = WinRMBackend
    except ImportError:
        logger.debug("WinRMBackend not available (pywinrm not installed)")


def get_backend(backend_type: str) -> VerificationBackend:
    """Create a VerificationBackend instance for the given type.

    Args:
        backend_type: One of "ssh", "docker", "http", "winrm".

    Returns:
        A VerificationBackend instance.

    Raises:
        ValueError: If *backend_type* is unknown or its dependencies
            are not installed.
    """
    _ensure_registered()

    cls = _BACKEND_CLASSES.get(backend_type)
    if cls is None:
        available = list(_BACKEND_CLASSES.keys())
        raise ValueError(
            f"Unknown backend type: '{backend_type}'. "
            f"Available: {available}"
        )

    logger.info("Creating %s backend", backend_type)

    try:
        return cls()
    except ImportError as exc:
        raise ValueError(
            f"Backend '{backend_type}' requires additional dependencies: {exc}"
        ) from exc
