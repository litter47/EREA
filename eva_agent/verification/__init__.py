"""Verification backends for exploit result validation.

Provides a pluggable abstraction for verifying exploit success
across different target environments: SSH, Docker Exec, WinRM, HTTP.
"""

from eva_agent.verification.backend import VerificationBackend
from eva_agent.verification.docker_backend import DockerExecBackend
from eva_agent.verification.http_backend import HTTPBackend
from eva_agent.verification.ssh_backend import SSHBackend
from eva_agent.verification.winrm_backend import WinRMBackend
from eva_agent.verification.factory import get_backend

__all__ = [
    "VerificationBackend",
    "SSHBackend",
    "DockerExecBackend",
    "WinRMBackend",
    "HTTPBackend",
    "get_backend",
]
