"""Report generator that produces JSON and Markdown verification reports.

The ``ReportGenerator`` consumes a fully populated ``TaskResult`` and
produces two output formats:

* **JSON** -- a structured dict suitable for API responses and programmatic
  consumption.
* **Markdown** -- a human-readable report with formatted sections, tables,
  and code blocks.
"""

from __future__ import annotations

import logging
from typing import Any

from eva_agent.task.models import TaskResult

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Produces structured JSON and human-readable Markdown verification
    reports from a completed ``TaskResult``."""

    # ------------------------------------------------------------------
    # JSON report
    # ------------------------------------------------------------------

    @staticmethod
    def generate_json(task_result: TaskResult) -> dict[str, Any]:
        """Produce a structured JSON report from a completed TaskResult.

        Args:
            task_result: The fully populated result of a verification task.

        Returns:
            A nested dict with sections: ``task_info``, ``exp_execution``,
            ``ssh_verification``, ``rule_engine``, ``llm_judgment``, and
            ``final_verdict``.
        """
        # ---- task_info -------------------------------------------------
        verify_type, target, command = ReportGenerator._extract_task_info(
            task_result
        )
        task_info: dict[str, Any] = {
            "verify_type": verify_type,
            "target": target,
            "command": command,
        }

        # ---- exp_execution ---------------------------------------------
        exp_execution: dict[str, Any] = {
            "exit_code": -1,
            "duration": 0.0,
            "stdout": "",
            "stderr": "",
        }
        if task_result.exp_result is not None:
            exp_execution["exit_code"] = task_result.exp_result.exit_code
            exp_execution["duration"] = task_result.exp_result.duration
            exp_execution["stdout"] = (
                task_result.exp_result.stdout[:2000]
                if task_result.exp_result.stdout
                else ""
            )
            exp_execution["stderr"] = (
                task_result.exp_result.stderr[:2000]
                if task_result.exp_result.stderr
                else ""
            )

        # ---- ssh_verification ------------------------------------------
        ssh_verification: list[dict[str, Any]] = []
        for check in (task_result.ssh_checks or []):
            ssh_verification.append(
                {
                    "check_name": check.check_name,
                    "passed": check.passed,
                    "details": check.details,
                }
            )

        # ---- rule_engine -----------------------------------------------
        rule_engine: dict[str, Any] = {
            "score": 0.0,
            "passed": False,
            "matched_rules": [],
        }
        if task_result.rule_score is not None:
            rule_engine["score"] = task_result.rule_score.score
            rule_engine["passed"] = task_result.rule_score.passed
            rule_engine["matched_rules"] = task_result.rule_score.matched_rules

        # ---- llm_judgment ----------------------------------------------
        llm_judgment: dict[str, Any] | None = None
        if task_result.llm_judgment is not None:
            llm_judgment = {
                "success": task_result.llm_judgment.success,
                "confidence": task_result.llm_judgment.confidence,
                "reasoning": task_result.llm_judgment.reasoning,
            }

        # ---- final_verdict ---------------------------------------------
        final_verdict: str = (
            task_result.final_verdict
            if task_result.final_verdict
            else "UNDETERMINED"
        )

        report: dict[str, Any] = {
            "task_info": task_info,
            "exp_execution": exp_execution,
            "ssh_verification": ssh_verification,
            "rule_engine": rule_engine,
            "llm_judgment": llm_judgment,
            "final_verdict": final_verdict,
        }

        logger.debug("Generated JSON report: final_verdict=%s", final_verdict)
        return report

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    @staticmethod
    def generate_markdown(task_result: TaskResult) -> str:
        """Produce a human-readable Markdown verification report.

        Args:
            task_result: The fully populated result of a verification task.

        Returns:
            A Markdown-formatted string with sections for task information,
            execution results, SSH verification, rule engine scores, LLM
            judgment (if available), and the final verdict.
        """
        lines: list[str] = []
        lines.append("# EVA-Agent Verification Report")
        lines.append("")

        # ---- Task Information ------------------------------------------
        lines.append("## Task Information")
        lines.append("")
        verify_type, target, command = ReportGenerator._extract_task_info(
            task_result
        )
        lines.append(f"- **Verify Type**: {verify_type}")
        lines.append(f"- **Target**: {target}")
        lines.append(f"- **Command**: `{command}`")
        lines.append("")

        # ---- EXP Execution Result --------------------------------------
        lines.append("## EXP Execution Result")
        lines.append("")
        if task_result.exp_result is not None:
            exp = task_result.exp_result
            lines.append(f"- **Exit Code**: `{exp.exit_code}`")
            lines.append(f"- **Duration**: `{exp.duration:.2f}s`")
            lines.append("")
            lines.append("### stdout")
            lines.append("")
            truncated_stdout = (
                exp.stdout[:2000] if exp.stdout else ""
            )
            lines.append("```")
            lines.append(truncated_stdout)
            lines.append("```")
            lines.append("")
            lines.append("### stderr")
            lines.append("")
            truncated_stderr = (
                exp.stderr[:2000] if exp.stderr else ""
            )
            lines.append("```")
            lines.append(truncated_stderr)
            lines.append("```")
        else:
            lines.append("*No execution result available.*")
        lines.append("")

        # ---- SSH Verification ------------------------------------------
        lines.append("## SSH Verification")
        lines.append("")
        ssh_checks = task_result.ssh_checks or []
        if ssh_checks:
            lines.append("| Check | Passed | Details |")
            lines.append("|-------|--------|---------|")
            for check in ssh_checks:
                passed_str = (
                    ":white_check_mark:" if check.passed else ":x:"
                )
                details_escaped = check.details.replace("|", "\\|")
                lines.append(
                    f"| {check.check_name} | {passed_str} | {details_escaped} |"
                )
        else:
            lines.append("*No SSH verification checks performed.*")
        lines.append("")

        # ---- Rule Engine Score -----------------------------------------
        lines.append("## Rule Engine Score")
        lines.append("")
        if task_result.rule_score is not None:
            rs = task_result.rule_score
            lines.append(f"- **Score**: `{rs.score:.4f}`")
            passed_str = (
                ":white_check_mark:" if rs.passed else ":x:"
            )
            lines.append(f"- **Passed**: {passed_str}")
            if rs.matched_rules:
                lines.append("- **Matched Rules**:")
                for rule in rs.matched_rules:
                    lines.append(f"  - `{rule}`")
            else:
                lines.append("- **Matched Rules**: *(none)*")
        else:
            lines.append("*No rule engine evaluation performed.*")
        lines.append("")

        # ---- LLM Judgment ----------------------------------------------
        lines.append("## LLM Judgment")
        lines.append("")
        if task_result.llm_judgment is not None:
            lj = task_result.llm_judgment
            success_str = (
                ":white_check_mark:" if lj.success else ":x:"
            )
            lines.append(f"- **Success**: {success_str}")
            lines.append(f"- **Confidence**: `{lj.confidence:.4f}`")
            lines.append("- **Reasoning**:")
            lines.append("")
            # Indent the reasoning block
            for paragraph in lj.reasoning.split("\n"):
                lines.append(f"  {paragraph}")
        else:
            lines.append("*LLM judgment was not performed (LLM client not available or disabled).*")
        lines.append("")

        # ---- Final Verdict ---------------------------------------------
        lines.append("## Final Verdict")
        lines.append("")
        final_verdict = (
            task_result.final_verdict
            if task_result.final_verdict
            else "UNDETERMINED"
        )
        lines.append(f"**{final_verdict}**")
        lines.append("")

        report_md = "\n".join(lines)
        logger.debug(
            "Generated Markdown report: final_verdict=%s", final_verdict
        )
        return report_md

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_task_info(
        task_result: TaskResult,
    ) -> tuple[str, str, str]:
        """Extract ``(verify_type, target, command)`` from task evidence.

        Looks for the ``"metadata"`` evidence item produced by the
        ``EvidenceBuilder`` during the verification pipeline.
        """
        verify_type: str = "unknown"
        target_ip: str = ""
        target_port: Any = ""
        command: str = ""

        for item in (task_result.evidence or []):
            if item.get("type") == "metadata":
                data = item.get("data", {})
                verify_type = data.get("verify_type", "unknown")
                target_ip = data.get("target_ip", "")
                target_port = data.get("target_port", "")
                command = data.get("execute_cmd", "")
                break

        target = (
            f"{target_ip}:{target_port}" if target_ip else "unknown"
        )
        return verify_type, target, command
