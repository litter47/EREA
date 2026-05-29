"""Tests for the EvidenceBuilder.

Verifies that exploit execution results and SSH verification results are
correctly assembled into structured evidence dicts used by the rule engine
and LLM judge.
"""

from __future__ import annotations

import pytest

from eva_agent.evidence.builder import EvidenceBuilder
from eva_agent.task.models import ExpResult, SSHCheck


class TestEvidenceBuilder:
    """Verify EvidenceBuilder.build() and build_summary()."""

    def setup_method(self) -> None:
        self.builder = EvidenceBuilder()

    # ------------------------------------------------------------------
    # build() tests
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_build_evidence_basic(
        self,
        mock_exp_result: ExpResult,
        mock_ssh_checks: list[SSHCheck],
    ):
        """Build evidence with exp_result and 3 ssh_checks.

        Expected: 1 exp_execution + 3 ssh_verification + 1 metadata = 5 items.
        """
        evidence = await self.builder.build(
            exp_result=mock_exp_result,
            ssh_checks=mock_ssh_checks,
            verify_type="rce",
            task_request={
                "target_ip": "192.168.1.100",
                "target_port": 22,
                "execute_cmd": "python exploit.py",
            },
        )

        assert isinstance(evidence, list)
        assert len(evidence) == 5  # 1 exp + 3 ssh + 1 metadata

    @pytest.mark.asyncio
    async def test_build_evidence_structure(
        self,
        mock_exp_result: ExpResult,
    ):
        """Verify each evidence item has type, source, data, timestamp fields."""
        evidence = await self.builder.build(
            exp_result=mock_exp_result,
            ssh_checks=[],
            verify_type="test",
            task_request={},
        )

        for item in evidence:
            assert "type" in item
            assert "source" in item
            assert "data" in item
            assert "timestamp" in item

        # Check specific types
        types = [item["type"] for item in evidence]
        assert "exp_execution" in types
        assert "metadata" in types

    @pytest.mark.asyncio
    async def test_build_with_empty_ssh_checks(
        self,
        mock_exp_result: ExpResult,
    ):
        """Build evidence with empty ssh_checks -> no ssh_verification items."""
        evidence = await self.builder.build(
            exp_result=mock_exp_result,
            ssh_checks=[],
            verify_type="rce",
            task_request={},
        )

        # Only exp_execution + metadata = 2 items
        assert len(evidence) == 2
        types = [item["type"] for item in evidence]
        assert "exp_execution" in types
        assert "ssh_verification" not in types
        assert "metadata" in types

    @pytest.mark.asyncio
    async def test_build_metadata_includes_all_fields(self):
        """Verify metadata evidence includes verify_type, target_ip, target_port, execute_cmd."""
        task_request = {
            "target_ip": "10.0.0.5",
            "target_port": 8080,
            "execute_cmd": "run.sh --flag",
        }
        evidence = await self.builder.build(
            exp_result=ExpResult(stdout="", stderr="", exit_code=0, duration=0.5),
            ssh_checks=[],
            verify_type="priv_esc",
            task_request=task_request,
        )

        # Find metadata item
        metadata = None
        for item in evidence:
            if item["type"] == "metadata":
                metadata = item
                break

        assert metadata is not None
        data = metadata["data"]
        assert data["verify_type"] == "priv_esc"
        assert data["target_ip"] == "10.0.0.5"
        assert data["target_port"] == 8080
        assert data["execute_cmd"] == "run.sh --flag"

    @pytest.mark.asyncio
    async def test_build_exp_data_content(self, mock_exp_result: ExpResult):
        """Verify the exp_execution data contains stdout, stderr, exit_code, duration."""
        evidence = await self.builder.build(
            exp_result=mock_exp_result,
            ssh_checks=[],
            verify_type="rce",
            task_request={},
        )

        exp_item = None
        for item in evidence:
            if item["type"] == "exp_execution":
                exp_item = item
                break

        assert exp_item is not None
        data = exp_item["data"]
        assert data["stdout"] == "test output"
        assert data["stderr"] == ""
        assert data["exit_code"] == 0
        assert data["duration"] == 1.5

    @pytest.mark.asyncio
    async def test_build_ssh_evidence_items(
        self,
        mock_exp_result: ExpResult,
        mock_ssh_checks: list[SSHCheck],
    ):
        """Verify each ssh_verification item has check_name, passed, details."""
        evidence = await self.builder.build(
            exp_result=mock_exp_result,
            ssh_checks=mock_ssh_checks,
            verify_type="rce",
            task_request={},
        )

        ssh_items = [item for item in evidence if item["type"] == "ssh_verification"]
        assert len(ssh_items) == 3

        for item, check in zip(ssh_items, mock_ssh_checks):
            data = item["data"]
            assert data["check_name"] == check.check_name
            assert data["passed"] == check.passed
            assert data["details"] == check.details

    # ------------------------------------------------------------------
    # build_summary() tests
    # ------------------------------------------------------------------

    def test_build_summary(
        self,
        mock_exp_result: ExpResult,
        mock_ssh_checks: list[SSHCheck],
        mock_evidence: list[dict],
    ):
        """Build summary and verify verify_type, exp_exit, ssh_checks count."""
        summary = self.builder.build_summary(
            evidence=mock_evidence,
            exp_result=mock_exp_result,
            ssh_checks=mock_ssh_checks,
        )

        assert isinstance(summary, dict)
        assert summary["verify_type"] == "rce"
        assert summary["exp_exit"] == 0
        assert summary["evidence"] == mock_evidence
        assert len(summary["ssh_checks"]) == 3

    def test_build_summary_counts(
        self,
        mock_exp_result: ExpResult,
        mock_ssh_checks: list[SSHCheck],
        mock_evidence: list[dict],
    ):
        """Verify total_ssh_checks and passed_ssh_checks are correct.

        mock_ssh_checks has 3 items: 2 passed, 1 failed.
        """
        summary = self.builder.build_summary(
            evidence=mock_evidence,
            exp_result=mock_exp_result,
            ssh_checks=mock_ssh_checks,
        )

        assert summary["total_ssh_checks"] == 3
        assert summary["passed_ssh_checks"] == 2

    def test_build_summary_no_ssh_checks(
        self,
        mock_exp_result: ExpResult,
    ):
        """Summary with no SSH checks -> counts are 0."""
        evidence = [
            {
                "type": "exp_execution",
                "source": "sandbox",
                "data": {
                    "stdout": "test",
                    "stderr": "",
                    "exit_code": 0,
                    "duration": 1.0,
                },
                "timestamp": "2025-01-01T00:00:00",
            },
            {
                "type": "metadata",
                "source": "request",
                "data": {
                    "verify_type": "rce",
                    "target_ip": "192.168.1.1",
                    "target_port": 22,
                    "execute_cmd": "run.sh",
                },
                "timestamp": "2025-01-01T00:00:00",
            },
        ]

        summary = self.builder.build_summary(
            evidence=evidence,
            exp_result=mock_exp_result,
            ssh_checks=[],
        )

        assert summary["total_ssh_checks"] == 0
        assert summary["passed_ssh_checks"] == 0
        assert len(summary["ssh_checks"]) == 0

    def test_build_summary_verify_type_from_metadata(
        self,
        mock_exp_result: ExpResult,
    ):
        """Summary extracts verify_type from metadata evidence."""
        evidence = [
            {
                "type": "exp_execution",
                "source": "sandbox",
                "data": {
                    "stdout": "test",
                    "stderr": "",
                    "exit_code": 0,
                    "duration": 1.0,
                },
                "timestamp": "2025-01-01T00:00:00",
            },
            {
                "type": "metadata",
                "source": "request",
                "data": {
                    "verify_type": "auth_bypass",
                    "target_ip": "10.0.0.1",
                    "target_port": 443,
                    "execute_cmd": "exploit.py",
                },
                "timestamp": "2025-01-01T00:00:00",
            },
        ]

        summary = self.builder.build_summary(
            evidence=evidence,
            exp_result=mock_exp_result,
            ssh_checks=[],
        )

        assert summary["verify_type"] == "auth_bypass"
