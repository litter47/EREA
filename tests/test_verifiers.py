"""Tests for SSH verification modules.

All verifiers are async functions.  Tests mock ``SSHVerificationAgent.run``
(or, for auth_bypass, ``httpx.AsyncClient``) to control the outputs that
the verifier modules process.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from eva_agent.ssh.verifiers.auth_bypass import verify as auth_bypass_verify
from eva_agent.ssh.verifiers.info_leak import verify as info_leak_verify
from eva_agent.ssh.verifiers.priv_esc import verify as priv_esc_verify
from eva_agent.ssh.verifiers.rce import verify as rce_verify
from eva_agent.task.models import SSHCheck


# ======================================================================
# Fixtures
# ======================================================================


@pytest.fixture
def mock_agent() -> AsyncMock:
    """Return an ``SSHVerificationAgent`` whose ``run`` method is an
    ``AsyncMock`` that returns (stdout, stderr, exit_code)."""
    agent = AsyncMock()
    agent.run = AsyncMock()
    return agent


@pytest.fixture
def mock_conn() -> MagicMock:
    """Return a mock SSH connection object."""
    return MagicMock()


# ======================================================================
# RCE verifier
# ======================================================================


class TestRCEVerifier:
    """Tests for ``eva_agent.ssh.verifiers.rce.verify``."""

    @pytest.mark.asyncio
    async def test_rce_verifier(self, mock_agent: AsyncMock, mock_conn: MagicMock):
        """All four RCE checks pass when the remote host shows signs of
        code execution."""
        # Each call to agent.run returns (stdout, stderr, exit_code).
        mock_agent.run.side_effect = [
            # 1. test -f /tmp/pwned -> file exists
            ("", "", 0),
            # 2. ps aux -> suspicious process (nc) visible
            (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      "
                "STAT START   TIME COMMAND\n"
                "root           1  0.0  0.0  12345  6789 ?        "
                "Ss   Jan01   0:00 systemd\n"
                "user          42  0.0  0.0   9876  5432 ?        "
                "S    Jan01   0:00 bash\n"
                "attacker     200  0.0  0.0   9999  1234 ?        "
                "S    12:34   0:00 nc\n",
                "",
                0,
            ),
            # 3. ss -tlnp -> unexpected listener on port 4444
            (
                "State    Recv-Q   Send-Q   Local Address:Port        "
                "Peer Address:Port        Process\n"
                "LISTEN   0        128      0.0.0.0:22                 "
                "0.0.0.0:*                users:((\"sshd\"))\n"
                "LISTEN   0        128      0.0.0.0:4444               "
                "0.0.0.0:*                users:((\"nc\"))\n",
                "",
                0,
            ),
            # 4. find /tmp -type f -mmin -5 -> recent files found
            ("/tmp/pwned\n/tmp/exploit.sh\n", "", 0),
        ]

        results: list[SSHCheck] = await rce_verify(mock_agent, mock_conn)

        assert len(results) == 4

        # file_side_effect
        assert results[0].check_name == "file_side_effect"
        assert results[0].passed is True
        assert "/tmp/pwned exists" in results[0].details

        # process_running
        assert results[1].check_name == "process_running"
        assert results[1].passed is True
        assert "Unexpected process" in results[1].details

        # network_listening
        assert results[2].check_name == "network_listening"
        assert results[2].passed is True
        assert "Unexpected listening ports" in results[2].details

        # new_files_recent
        assert results[3].check_name == "new_files_recent"
        assert results[3].passed is True
        assert "Recently created files" in results[3].details

    @pytest.mark.asyncio
    async def test_rce_file_side_effect(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """Only the ``file_side_effect`` check passes; all others fail."""
        mock_agent.run.side_effect = [
            # 1. test -f /tmp/pwned -> exists (passes)
            ("", "", 0),
            # 2. ps aux -> fails (exit code != 0)
            ("", "permission denied", 1),
            # 3. ss -tlnp -> only sshd listening
            (
                "State    Recv-Q   Send-Q   Local Address:Port        "
                "Peer Address:Port        Process\n"
                "LISTEN   0        128      0.0.0.0:22                 "
                "0.0.0.0:*                users:((\"sshd\"))\n",
                "",
                0,
            ),
            # 4. find /tmp -> no recent files
            ("", "", 0),
        ]

        results: list[SSHCheck] = await rce_verify(mock_agent, mock_conn)

        assert len(results) == 4

        # file_side_effect passes
        assert results[0].check_name == "file_side_effect"
        assert results[0].passed is True

        # All others fail
        assert results[1].check_name == "process_running"
        assert results[1].passed is False

        assert results[2].check_name == "network_listening"
        assert results[2].passed is False

        assert results[3].check_name == "new_files_recent"
        assert results[3].passed is False

    @pytest.mark.asyncio
    async def test_rce_no_side_effect(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """All RCE checks fail when there is no evidence of exploitation."""
        mock_agent.run.side_effect = [
            # 1. test -f /tmp/pwned -> does not exist
            ("", "", 1),
            # 2. ps aux -> only expected processes
            (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      "
                "STAT START   TIME COMMAND\n"
                "root           1  0.0  0.0  12345  6789 ?        "
                "Ss   Jan01   0:00 systemd\n"
                "root          67  0.0  0.0   5678  1234 ?        "
                "Ss   Jan01   0:00 sshd\n",
                "",
                0,
            ),
            # 3. ss -tlnp -> only sshd on :22
            (
                "State    Recv-Q   Send-Q   Local Address:Port        "
                "Peer Address:Port        Process\n"
                "LISTEN   0        128      0.0.0.0:22                 "
                "0.0.0.0:*                users:((\"sshd\"))\n",
                "",
                0,
            ),
            # 4. find /tmp -> nothing
            ("", "", 0),
        ]

        results: list[SSHCheck] = await rce_verify(mock_agent, mock_conn)

        assert len(results) == 4
        for check in results:
            assert check.passed is False, (
                f"{check.check_name} unexpectedly passed: {check.details}"
            )


# ======================================================================
# Information leakage verifier
# ======================================================================


class TestInfoLeakVerifier:
    """Tests for ``eva_agent.ssh.verifiers.info_leak.verify``."""

    @pytest.mark.asyncio
    async def test_info_leak_verifier(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """All info-leak checks pass when sensitive data is readable."""
        # The verifier runs 1 x shadow + 1 x passwd + 19 x sensitive_paths
        # = 21 commands.
        side_effect: list[tuple[str, str, int]] = []

        # shadow_readable: /etc/shadow contains root entry
        side_effect.append(
            (
                "root:$6$saltsalt$hashhashhash:19234:0:99999:7:::",
                "",
                0,
            )
        )

        # passwd_contents: /etc/passwd with a few users
        side_effect.append(
            (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
                "",
                0,
            )
        )

        # sensitive_configs: make most inaccessible, a few readable
        for idx in range(19):
            if idx < 2:
                # First two paths readable
                side_effect.append(("DB_PASSWORD=secret\n", "", 0))
            else:
                side_effect.append(("", "", 1))

        mock_agent.run.side_effect = side_effect

        results: list[SSHCheck] = await info_leak_verify(mock_agent, mock_conn)

        assert len(results) == 3

        # shadow_readable
        assert results[0].check_name == "shadow_readable"
        assert results[0].passed is True
        assert "root" in results[0].details

        # passwd_contents
        assert results[1].check_name == "passwd_contents"
        assert results[1].passed is True
        assert "Total entries" in results[1].details

        # sensitive_configs
        assert results[2].check_name == "sensitive_configs"
        assert results[2].passed is True
        assert "Readable sensitive" in results[2].details

    @pytest.mark.asyncio
    async def test_info_leak_shadow_readable(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """shadow_readable passes when /etc/shadow contains root entries."""
        side_effect: list[tuple[str, str, int]] = [
            # shadow readable with root hash
            (
                "root:$6$abcdef$1234567890abcdef:19234:0:99999:7:::",
                "",
                0,
            ),
            # passwd readable (but we just check shadow in this test)
            ("root:x:0:0:root:/root:/bin/bash\n", "", 0),
        ]
        # Sensitive configs: all fail
        for _ in range(19):
            side_effect.append(("", "", 1))

        mock_agent.run.side_effect = side_effect

        results: list[SSHCheck] = await info_leak_verify(mock_agent, mock_conn)

        assert results[0].check_name == "shadow_readable"
        assert results[0].passed is True
        assert "root:" in results[0].details


# ======================================================================
# Privilege escalation verifier
# ======================================================================


class TestPrivEscVerifier:
    """Tests for ``eva_agent.ssh.verifiers.priv_esc.verify``."""

    @pytest.mark.asyncio
    async def test_priv_esc_verifier(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """Privilege escalation checks pass when ``whoami`` returns root.

        The ``current_user`` check requires ``uid=0`` in the ``id``
        output, so both commands are mocked accordingly.
        """
        mock_agent.run.side_effect = [
            # whoami -> root
            ("root", "", 0),
            # id -> uid=0
            ("uid=0(root) gid=0(root) groups=0(root)", "", 0),
            # sudo -n true -> available
            ("sudo_available", "", 0),
            # id -u (for uid_changed, triggered by evidence)
            ("0", "", 0),
            # ps -U root -> root processes visible
            (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:01 systemd\n"
                "  100 ?        00:00:00 sshd\n",
                "",
                0,
            ),
        ]

        evidence = {"baseline_uid": "1000"}
        results: list[SSHCheck] = await priv_esc_verify(
            mock_agent, mock_conn, evidence
        )

        # Discover check names
        check_map = {c.check_name: c for c in results}

        # current_user passes because uid=0 in id output
        assert check_map["current_user"].passed is True
        assert "uid=0" in check_map["current_user"].details

        # sudo_access passes
        assert check_map["sudo_access"].passed is True

        # uid_changed passes (baseline 1000 vs current 0)
        assert check_map["uid_changed"].passed is True

        # root_processes passes
        assert check_map["root_processes"].passed is True

    @pytest.mark.asyncio
    async def test_priv_esc_root(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """current_user check passes when ``id`` shows uid=0."""
        mock_agent.run.side_effect = [
            # whoami -> not root (this alone is not sufficient)
            ("ubuntu", "", 0),
            # id -> shows uid=0 (elevated)
            ("uid=0(root) gid=0(root) groups=0(root)", "", 0),
            # sudo -n true -> not available
            ("", "", 1),
            # sudo -l -> not allowed
            ("User ubuntu is not allowed to run sudo", "", 0),
            # ps -U root
            ("  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n", "", 0),
        ]

        results: list[SSHCheck] = await priv_esc_verify(mock_agent, mock_conn)

        check_map = {c.check_name: c for c in results}
        assert check_map["current_user"].passed is True
        assert "uid=0" in check_map["current_user"].details
        assert "ubuntu" in check_map["current_user"].details


# ======================================================================
# Authentication bypass verifier
# ======================================================================


class TestAuthBypassVerifier:
    """Tests for ``eva_agent.ssh.verifiers.auth_bypass.verify``."""

    @pytest.mark.asyncio
    async def test_auth_bypass_verifier(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """access_protected passes when httpx returns HTTP 200."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.text = (
            "<html><title>Admin Dashboard</title>"
            "<body>Welcome, Administrator</body></html>"
        )
        mock_headers = MagicMock()
        mock_headers.get_list.return_value = []
        mock_headers.items.return_value = []
        mock_response.headers = mock_headers

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response

        evidence = {
            "target_ip": "192.168.1.100",
            "target_port": 8080,
            "target_path": "/admin",
            "expected_status": 200,
            "previous_status": 401,
        }

        with patch(
            "httpx.AsyncClient",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client_instance)
            ),
        ):
            results: list[SSHCheck] = await auth_bypass_verify(
                mock_agent, mock_conn, evidence
            )

        check_map = {c.check_name: c for c in results}

        assert check_map["access_protected"].passed is True
        assert "200" in check_map["access_protected"].details

        # content_indicators passes because body contains admin indicators
        assert check_map["content_indicators"].passed is True

        # session_check fails because no Set-Cookie
        assert check_map["session_check"].passed is False

    @pytest.mark.asyncio
    async def test_auth_bypass_403(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """access_protected fails when httpx returns HTTP 403."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 403
        mock_response.text = "<html>Forbidden</html>"
        mock_headers = MagicMock()
        mock_headers.get_list.return_value = []
        mock_headers.items.return_value = []
        mock_response.headers = mock_headers

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response

        evidence = {
            "target_ip": "10.0.0.1",
            "target_port": 80,
            "expected_status": 200,
            "previous_status": 403,
        }

        with patch(
            "httpx.AsyncClient",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client_instance)
            ),
        ):
            results: list[SSHCheck] = await auth_bypass_verify(
                mock_agent, mock_conn, evidence
            )

        check_map = {c.check_name: c for c in results}

        assert check_map["access_protected"].passed is False
        assert "403" in check_map["access_protected"].details

    @pytest.mark.asyncio
    async def test_auth_bypass_missing_evidence(
        self, mock_agent: AsyncMock, mock_conn: MagicMock
    ):
        """Missing ``target_ip`` in evidence raises ValueError."""
        evidence: dict = {}  # No target_ip, no target_port

        with pytest.raises(
            ValueError,
            match="requires 'target_ip' and 'target_port'",
        ):
            await auth_bypass_verify(mock_agent, mock_conn, evidence)
