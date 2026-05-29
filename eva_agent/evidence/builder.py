"""Evidence builder that aggregates exploit execution results,
SSH verification results, and task metadata into structured evidence
items used by the rule engine and LLM judge.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from eva_agent.task.models import ExpResult, SSHCheck


class EvidenceBuilder:
    """Builds structured evidence items from sandbox execution output,
    SSH verification results, and task metadata.
    """

    async def build(
        self,
        exp_result: ExpResult,
        ssh_checks: list[SSHCheck],
        verify_type: str,
        task_request: dict,
    ) -> list[dict]:
        """Merge EXP execution results, SSH verification results, and
        task metadata into a list of evidence dicts.

        Args:
            exp_result: Raw output from the sandboxed exploit execution.
            ssh_checks: List of SSH-based verification check results.
            verify_type: The type of verification being performed.
            task_request: The original task request dict containing
                metadata such as target_ip, target_port, execute_cmd.

        Returns:
            A list of evidence dicts, each with keys:
                type, source, data, timestamp
        """
        evidence: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()

        # 1. EXP execution evidence
        exp_evidence: dict[str, Any] = {
            "type": "exp_execution",
            "source": "sandbox",
            "data": {
                "stdout": exp_result.stdout,
                "stderr": exp_result.stderr,
                "exit_code": exp_result.exit_code,
                "duration": exp_result.duration,
            },
            "timestamp": now,
        }
        evidence.append(exp_evidence)

        # 2. SSH verification evidence (one item per check)
        for check in ssh_checks:
            ssh_evidence: dict[str, Any] = {
                "type": "ssh_verification",
                "source": "ssh",
                "data": {
                    "check_name": check.check_name,
                    "passed": check.passed,
                    "details": check.details,
                },
                "timestamp": now,
            }
            evidence.append(ssh_evidence)

        # 3. Metadata evidence
        metadata_evidence: dict[str, Any] = {
            "type": "metadata",
            "source": "request",
            "data": {
                "verify_type": verify_type,
                "target_ip": task_request.get("target_ip", ""),
                "target_port": task_request.get("target_port", 0),
                "execute_cmd": task_request.get("execute_cmd", ""),
            },
            "timestamp": now,
        }
        evidence.append(metadata_evidence)

        return evidence

    @staticmethod
    def build_summary(
        evidence: list[dict],
        exp_result: ExpResult,
        ssh_checks: list[SSHCheck],
    ) -> dict:
        """Build a human-readable summary dict from the collected evidence.

        Args:
            evidence: The full list of evidence dicts.
            exp_result: Raw exploit execution result.
            ssh_checks: List of SSH verification check results.

        Returns:
            A summary dict containing:
                verify_type, exp_exit, ssh_checks, evidence,
                total_ssh_checks, passed_ssh_checks
        """
        total_ssh = len(ssh_checks)
        passed_ssh = sum(1 for c in ssh_checks if c.passed)

        # Extract verify_type from metadata evidence if present
        verify_type = "unknown"
        for item in evidence:
            if item.get("type") == "metadata":
                verify_type = item["data"].get("verify_type", "unknown")
                break

        return {
            "verify_type": verify_type,
            "exp_exit": exp_result.exit_code,
            "ssh_checks": [
                {
                    "check_name": c.check_name,
                    "passed": c.passed,
                    "details": c.details,
                }
                for c in ssh_checks
            ],
            "evidence": evidence,
            "total_ssh_checks": total_ssh,
            "passed_ssh_checks": passed_ssh,
        }
