"""Tests for the ``ReportGenerator`` class.

Validates that ``generate_json`` and ``generate_markdown`` produce
the expected structured output from a ``TaskResult``.
"""

from __future__ import annotations

from eva_agent.report.generator import ReportGenerator
from eva_agent.task.models import (
    ExpResult,
    LLMJudgment,
    RuleScore,
    SSHCheck,
    TaskResult,
)


class TestGenerateJson:
    """Tests for ``ReportGenerator.generate_json``."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _task_result(
        exp_result: ExpResult | None = None,
        ssh_checks: list[SSHCheck] | None = None,
        rule_score: RuleScore | None = None,
        llm_judgment: LLMJudgment | None = None,
        final_verdict: str = "UNDETERMINED",
        evidence: list[dict] | None = None,
    ) -> TaskResult:
        """Build a ``TaskResult`` with sensible defaults."""
        if evidence is None:
            evidence = [
                {
                    "type": "metadata",
                    "data": {
                        "verify_type": "rce",
                        "target_ip": "10.0.0.1",
                        "target_port": 22,
                        "execute_cmd": "./exploit.sh",
                    },
                }
            ]
        return TaskResult(
            exp_result=exp_result,
            ssh_checks=ssh_checks or [],
            evidence=evidence,
            rule_score=rule_score,
            llm_judgment=llm_judgment,
            final_verdict=final_verdict,
        )

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_generate_json(self):
        """JSON report contains all sections when the result is fully
        populated."""
        task_result = self._task_result(
            exp_result=ExpResult(
                stdout="exploit ran OK",
                stderr="",
                exit_code=0,
                duration=2.5,
            ),
            ssh_checks=[
                SSHCheck(
                    check_name="file_side_effect",
                    passed=True,
                    details="/tmp/pwned exists",
                ),
                SSHCheck(
                    check_name="process_running",
                    passed=False,
                    details="No suspicious processes",
                ),
            ],
            rule_score=RuleScore(
                score=0.85,
                passed=True,
                matched_rules=["RULE-001", "RULE-002"],
            ),
            llm_judgment=LLMJudgment(
                success=True,
                confidence=0.92,
                reasoning="The exploit behavior matches known RCE patterns.",
            ),
            final_verdict="SUCCESS",
        )

        report = ReportGenerator.generate_json(task_result)

        # Top-level keys
        assert "task_info" in report
        assert "exp_execution" in report
        assert "ssh_verification" in report
        assert "rule_engine" in report
        assert "llm_judgment" in report
        assert "final_verdict" in report

        # task_info
        assert report["task_info"]["verify_type"] == "rce"
        assert report["task_info"]["target"] == "10.0.0.1:22"
        assert report["task_info"]["command"] == "./exploit.sh"

        # exp_execution
        assert report["exp_execution"]["exit_code"] == 0
        assert report["exp_execution"]["duration"] == 2.5
        assert report["exp_execution"]["stdout"] == "exploit ran OK"
        assert report["exp_execution"]["stderr"] == ""

        # ssh_verification
        assert len(report["ssh_verification"]) == 2
        assert report["ssh_verification"][0]["check_name"] == "file_side_effect"
        assert report["ssh_verification"][0]["passed"] is True
        assert report["ssh_verification"][1]["check_name"] == "process_running"
        assert report["ssh_verification"][1]["passed"] is False

        # rule_engine
        assert report["rule_engine"]["score"] == 0.85
        assert report["rule_engine"]["passed"] is True
        assert report["rule_engine"]["matched_rules"] == ["RULE-001", "RULE-002"]

        # llm_judgment
        assert report["llm_judgment"]["success"] is True
        assert report["llm_judgment"]["confidence"] == 0.92
        assert (
            report["llm_judgment"]["reasoning"]
            == "The exploit behavior matches known RCE patterns."
        )

        # final_verdict
        assert report["final_verdict"] == "SUCCESS"

    def test_generate_json_no_llm(self):
        """When ``llm_judgment`` is ``None``, the JSON key has the value
        ``None``."""
        task_result = self._task_result(
            exp_result=ExpResult(stdout="", stderr="", exit_code=0, duration=0.0),
            final_verdict="FAILED",
        )

        report = ReportGenerator.generate_json(task_result)

        assert report["llm_judgment"] is None
        assert report["final_verdict"] == "FAILED"

    def test_generate_json_undetermined(self):
        """A ``TaskResult`` with ``final_verdict="UNDETERMINED"`` produces
        a JSON report reflecting that."""
        task_result = self._task_result()

        report = ReportGenerator.generate_json(task_result)

        assert report["final_verdict"] == "UNDETERMINED"
        # Default values for empty sections
        assert report["exp_execution"]["exit_code"] == -1
        assert report["exp_execution"]["stdout"] == ""
        assert report["ssh_verification"] == []
        assert report["rule_engine"]["score"] == 0.0
        assert report["rule_engine"]["passed"] is False
        assert report["llm_judgment"] is None

    def test_json_stdout_truncation(self):
        """stdout longer than 2000 characters is truncated in the JSON
        report."""
        long_stdout = "A" * 2500
        task_result = self._task_result(
            exp_result=ExpResult(
                stdout=long_stdout,
                stderr="",
                exit_code=0,
                duration=1.0,
            ),
        )

        report = ReportGenerator.generate_json(task_result)

        assert len(report["exp_execution"]["stdout"]) == 2000
        assert report["exp_execution"]["stdout"] == "A" * 2000

    def test_json_stderr_truncation(self):
        """stderr longer than 2000 characters is truncated in the JSON
        report."""
        long_stderr = "B" * 2500
        task_result = self._task_result(
            exp_result=ExpResult(
                stdout="ok",
                stderr=long_stderr,
                exit_code=1,
                duration=0.5,
            ),
        )

        report = ReportGenerator.generate_json(task_result)

        assert len(report["exp_execution"]["stderr"]) == 2000
        assert report["exp_execution"]["stderr"] == "B" * 2000


class TestGenerateMarkdown:
    """Tests for ``ReportGenerator.generate_markdown``."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _task_result(
        exp_result: ExpResult | None = None,
        ssh_checks: list[SSHCheck] | None = None,
        rule_score: RuleScore | None = None,
        llm_judgment: LLMJudgment | None = None,
        final_verdict: str = "SUCCESS",
        evidence: list[dict] | None = None,
    ) -> TaskResult:
        if evidence is None:
            evidence = [
                {
                    "type": "metadata",
                    "data": {
                        "verify_type": "priv_esc",
                        "target_ip": "192.168.1.50",
                        "target_port": 2222,
                        "execute_cmd": "./privesc.sh",
                    },
                }
            ]
        return TaskResult(
            exp_result=exp_result,
            ssh_checks=ssh_checks or [],
            evidence=evidence,
            rule_score=rule_score,
            llm_judgment=llm_judgment,
            final_verdict=final_verdict,
        )

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_generate_markdown(self):
        """Markdown report contains all expected section headers."""
        task_result = self._task_result(
            exp_result=ExpResult(
                stdout="exploit output here",
                stderr="",
                exit_code=0,
                duration=3.0,
            ),
            ssh_checks=[
                SSHCheck(
                    check_name="current_user",
                    passed=True,
                    details="Current user is root.",
                ),
            ],
            rule_score=RuleScore(
                score=0.9,
                passed=True,
                matched_rules=["RULE-PRIVESC-001"],
            ),
            llm_judgment=LLMJudgment(
                success=True,
                confidence=0.88,
                reasoning="Confirmed privilege escalation.",
            ),
        )

        md = ReportGenerator.generate_markdown(task_result)

        # Section headers
        assert "# EVA-Agent Verification Report" in md
        assert "## Task Information" in md
        assert "## EXP Execution Result" in md
        assert "## SSH Verification" in md
        assert "## Rule Engine Score" in md
        assert "## LLM Judgment" in md
        assert "## Final Verdict" in md

        # Metadata
        assert "priv_esc" in md
        assert "192.168.1.50" in md
        assert "./privesc.sh" in md

        # Final verdict
        assert "**SUCCESS**" in md

    def test_generate_markdown_table(self):
        """SSH verification section contains a pipe-delimited table."""
        task_result = self._task_result(
            ssh_checks=[
                SSHCheck(
                    check_name="shadow_readable",
                    passed=True,
                    details="/etc/shadow is readable.",
                ),
                SSHCheck(
                    check_name="passwd_contents",
                    passed=False,
                    details="No passwd data.",
                ),
            ],
        )

        md = ReportGenerator.generate_markdown(task_result)

        # Table header and separator
        assert "| Check | Passed | Details |" in md
        assert "|-------|--------|---------|" in md

        # Table rows
        assert "shadow_readable" in md
        assert "passwd_contents" in md
        assert "/etc/shadow is readable." in md
        assert "No passwd data." in md

    def test_markdown_no_llm(self):
        """When ``llm_judgment`` is ``None``, the LLM Judgment section
        shows a fallback message instead of an error."""
        task_result = self._task_result(
            llm_judgment=None,
        )

        md = ReportGenerator.generate_markdown(task_result)

        # The section header is always emitted
        assert "## LLM Judgment" in md
        # Fallback text
        assert "was not performed" in md
        # No LLM-specific fields
        assert "**Success**" not in md
        assert "**Confidence**" not in md
