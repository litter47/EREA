"""Tests for the pluggable verification backends and backend factory."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from eva_agent.verification.backend import VerificationBackend
from eva_agent.verification.factory import (
    _BACKEND_CLASSES,
    _ensure_registered,
    get_backend,
)


class TestBackendFactory:
    """Tests for the backend factory function."""

    def setup_method(self) -> None:
        """Reset the registry before each test."""
        _BACKEND_CLASSES.clear()

    def test_get_ssh_backend(self) -> None:
        backend = get_backend("ssh")
        assert backend.backend_type == "ssh"
        from eva_agent.verification.ssh_backend import SSHBackend

        assert isinstance(backend, SSHBackend)

    def test_get_docker_backend_mocked(self) -> None:
        """Docker backend -- mock docker.from_env to avoid real Docker."""
        with patch("docker.from_env"):
            backend = get_backend("docker")
            assert backend.backend_type == "docker"

    def test_get_http_backend(self) -> None:
        backend = get_backend("http")
        assert backend.backend_type == "http"

    def test_get_winrm_backend_module_not_installed(self) -> None:
        """WinRM backend raises ValueError if pywinrm is unavailable at
        instantiation time."""
        # The WinRMBackend class is importable (local module), but
        # __init__ calls _check_deps which tries 'import winrm'.
        _BACKEND_CLASSES.clear()

        from eva_agent.verification.winrm_backend import WinRMBackend

        with patch.object(
            WinRMBackend,
            "_check_deps",
            side_effect=ImportError("No module named 'winrm'"),
        ):
            with pytest.raises(ValueError, match="additional dependencies"):
                get_backend("winrm")

    def test_get_unknown_backend_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown backend"):
            get_backend("unknown_type")

    def test_get_backend_with_hosting(self) -> None:
        """Test get_backend with mocked docker."""
        import sys  # noqa: F401

        with patch("docker.from_env"):
            backend = get_backend("docker")
            assert backend is not None


class TestSSHBackend:
    """Tests for SSHBackend."""

    @pytest.mark.asyncio
    async def test_connect_password(self) -> None:
        from eva_agent.verification.ssh_backend import SSHBackend

        backend = SSHBackend()
        with patch("asyncssh.connect", new_callable=AsyncMock) as mock_connect:
            target = {
                "host": "10.0.0.1",
                "port": 22,
                "username": "root",
                "password": "secret",
            }
            await backend.connect(target)
            mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_key_content(self) -> None:
        from eva_agent.verification.ssh_backend import SSHBackend

        backend = SSHBackend()
        with patch("asyncssh.connect", new_callable=AsyncMock) as mock_connect, patch(
            "asyncssh.import_private_key"
        ) as mock_import_key:
            target = {
                "host": "10.0.0.1",
                "username": "root",
                "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
            }
            await backend.connect(target)
            mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_no_credentials(self) -> None:
        from eva_agent.verification.ssh_backend import SSHBackend

        backend = SSHBackend()
        target = {"host": "10.0.0.1", "username": "root"}
        with pytest.raises(ValueError, match="password.*ssh_key.*client_keys"):
            await backend.connect(target)

    @pytest.mark.asyncio
    async def test_connect_missing_host(self) -> None:
        from eva_agent.verification.ssh_backend import SSHBackend

        backend = SSHBackend()
        target = {"username": "root", "password": "x"}
        with pytest.raises(ValueError, match="host"):
            await backend.connect(target)

    @pytest.mark.asyncio
    async def test_run_returns_decoded_output(self) -> None:
        from eva_agent.verification.ssh_backend import SSHBackend

        backend = SSHBackend()
        mock_session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.stdout = b"hello\n"
        mock_result.stderr = b"error\n"
        mock_result.exit_code = 0
        mock_session.run = AsyncMock(return_value=mock_result)

        stdout, stderr, exit_code = await backend.run(mock_session, "echo hello")
        assert "hello" in stdout
        assert "error" in stderr
        assert exit_code == 0

    @pytest.mark.asyncio
    async def test_disconnect_closes_session(self) -> None:
        from eva_agent.verification.ssh_backend import SSHBackend

        backend = SSHBackend()
        mock_session = MagicMock()
        await backend.disconnect(mock_session)
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_dispatches_to_correct_verifier(self) -> None:
        from eva_agent.verification.ssh_backend import SSHBackend

        backend = SSHBackend()
        mock_session = AsyncMock()

        checks = await backend.verify(mock_session, "rce", {})
        assert isinstance(checks, list)


class TestDockerExecBackend:
    """Tests for DockerExecBackend."""

    def setup_method(self) -> None:
        self._docker_patch = patch("docker.from_env")
        self._mock_docker = self._docker_patch.start()

    def teardown_method(self) -> None:
        self._docker_patch.stop()

    @pytest.mark.asyncio
    async def test_connect_by_name(self) -> None:
        from eva_agent.verification.docker_backend import DockerExecBackend

        backend = DockerExecBackend()
        # Now docker.from_env is mocked so container lookup works
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        backend._client.containers.get = MagicMock(return_value=mock_container)

        target = {"container_name": "target_ctr"}
        session = await backend.connect(target)

        backend._client.containers.get.assert_called_once_with("target_ctr")
        assert session is mock_container

    @pytest.mark.asyncio
    async def test_connect_missing_name(self) -> None:
        from eva_agent.verification.docker_backend import DockerExecBackend

        backend = DockerExecBackend()
        with pytest.raises(ValueError, match="container_name"):
            await backend.connect({})

    @pytest.mark.asyncio
    async def test_run_executes_command(self) -> None:
        from eva_agent.verification.docker_backend import DockerExecBackend

        backend = DockerExecBackend()
        mock_container = MagicMock()
        mock_result = MagicMock()
        mock_result.output = b"output\n"
        mock_result.exit_code = 0
        mock_container.exec_run = MagicMock(return_value=mock_result)

        stdout, stderr, exit_code = await backend.run(mock_container, "whoami")
        assert "output" in stdout
        assert exit_code == 0

    @pytest.mark.asyncio
    async def test_disconnect_noop(self) -> None:
        from eva_agent.verification.docker_backend import DockerExecBackend

        backend = DockerExecBackend()
        # Should not raise
        await backend.disconnect(MagicMock())


class TestWinRMBackend:
    """Tests for WinRMBackend."""

    @pytest.mark.asyncio
    async def test_connect_winrm(self) -> None:
        """Should raise ImportError if pywinrm not installed,
        but if we mock winrm, it should work."""
        with patch.dict("sys.modules", {"winrm": MagicMock()}):
            from eva_agent.verification.winrm_backend import WinRMBackend

            backend = WinRMBackend()
            assert backend.backend_type == "winrm"

    @pytest.mark.asyncio
    async def test_missing_host(self) -> None:
        with patch.dict("sys.modules", {"winrm": MagicMock()}):
            from eva_agent.verification.winrm_backend import WinRMBackend

            backend = WinRMBackend()
            with pytest.raises(ValueError, match="host"):
                await backend.connect({})

    def test_translate_cmd(self) -> None:
        with patch.dict("sys.modules", {"winrm": MagicMock()}):
            from eva_agent.verification.winrm_backend import WinRMBackend

            backend = WinRMBackend()
            result = backend._translate_cmd("whoami")
            assert "whoami" in result
            result2 = backend._translate_cmd("cat /etc/shadow")
            assert "type" in result2.lower()


class TestHTTPBackend:
    """Tests for HTTPBackend."""

    @pytest.mark.asyncio
    async def test_connect_returns_session_dict(self) -> None:
        from eva_agent.verification.http_backend import HTTPBackend

        backend = HTTPBackend()
        session = await backend.connect({"host": "10.0.0.1", "port": 8080})
        assert session["host"] == "10.0.0.1"
        assert session["port"] == 8080
        assert session["base_url"] == "http://10.0.0.1:8080"

    @pytest.mark.asyncio
    async def test_connect_missing_host(self) -> None:
        from eva_agent.verification.http_backend import HTTPBackend

        backend = HTTPBackend()
        with pytest.raises(ValueError, match="host"):
            await backend.connect({})

    @pytest.mark.asyncio
    async def test_run_http_get(self) -> None:
        from eva_agent.verification.http_backend import HTTPBackend

        backend = HTTPBackend()
        session = {
            "host": "10.0.0.1",
            "port": 80,
            "base_url": "http://10.0.0.1:80",
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "<html>admin</html>"
            mock_response.headers = {"content-type": "text/html"}
            mock_response.content = b"<html>admin</html>"
            mock_get.return_value = mock_response

            stdout, stderr, exit_code = await backend.run(session, "/admin")
            assert "200" in stdout
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_run_403_response(self) -> None:
        from eva_agent.verification.http_backend import HTTPBackend

        backend = HTTPBackend()
        session = {
            "host": "10.0.0.1",
            "port": 80,
            "base_url": "http://10.0.0.1:80",
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 403
            mock_response.text = "Forbidden"
            mock_response.headers = {}
            mock_response.content = b"Forbidden"
            mock_get.return_value = mock_response

            stdout, stderr, exit_code = await backend.run(session, "/admin")
            assert exit_code == 1

    @pytest.mark.asyncio
    async def test_run_timeout(self) -> None:
        import httpx

        from eva_agent.verification.http_backend import HTTPBackend

        backend = HTTPBackend()
        session = {
            "host": "10.0.0.1",
            "port": 80,
            "base_url": "http://10.0.0.1:80",
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timeout")
            stdout, stderr, exit_code = await backend.run(session, "/admin")
            assert exit_code == -1

    @pytest.mark.asyncio
    async def test_disconnect_noop(self) -> None:
        from eva_agent.verification.http_backend import HTTPBackend

        backend = HTTPBackend()
        await backend.disconnect({})  # Should not raise


class TestVerificationBackendAbstract:
    """Verify the abstract base cannot be instantiated directly."""

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            VerificationBackend()  # type: ignore[abstract]
