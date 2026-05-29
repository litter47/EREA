"""Background worker that orchestrates the full exploit-verification pipeline.

The ``ExecutionWorker`` takes a submitted ``Task`` and runs it through
every stage of verification:

1. Sandboxed exploit execution (via Docker)
2. Multi-backend remote verification (SSH, Docker exec, WinRM, HTTP)
3. Structured evidence assembly
4. Rule-engine evaluation
5. Optional LLM judgment
6. Report generation (JSON + Markdown)
7. Final-verdict computation

All errors are caught internally so the worker never crashes.  Timeouts
are enforced via ``asyncio.wait_for`` using the configured task timeout.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from eva_agent.config.settings import Settings
from eva_agent.evidence.builder import EvidenceBuilder
from eva_agent.llm.client import LLMClient
from eva_agent.llm.config import load_llm_config
from eva_agent.llm.factory import LLMClientFactory
from eva_agent.report.generator import ReportGenerator
from eva_agent.rules.engine import RuleEngine
from eva_agent.rules.loader import RuleLoader
from eva_agent.sandbox.executor import SandboxExecutor
from eva_agent.verification.backend import VerificationBackend
from eva_agent.verification.factory import get_backend
from eva_agent.task.models import (
    ExpResult,
    LLMJudgment,
    RuleScore,
    SSHCheck,
    Task,
    TaskResult,
    TaskStatus,
)

logger = logging.getLogger(__name__)


class ExecutionWorker:
    """Orchestrates the full exploit-verification pipeline for a single task.

    The worker owns instances of every pipeline component and wires them
    together in the ``run()`` coroutine.  All errors are caught so the
    worker never propagates unhandled exceptions to its caller.

    Args:
        settings: Application settings (Docker image, timeout, etc.).
        task_manager: The ``TaskManager`` instance (may be used for
            status updates or callbacks if needed).
        rule_dir: Path to the directory containing YAML rule files.
        config_dir: Path to the configuration directory (e.g. for
            ``llm.yaml``).
    """

    def __init__(
        self,
        settings: Settings,
        task_manager: Any = None,  # noqa: ANN401 -- TaskManager, optional
        rule_dir: str = "config/rules",
        config_dir: str = "config",
    ) -> None:
        self._settings = settings
        self._task_manager = task_manager

        # Pipeline components
        self.sandbox_executor = SandboxExecutor(
            image_name=settings.docker_image,
            timeout=settings.task_timeout,
        )
        self.evidence_builder = EvidenceBuilder()
        self.rule_loader = RuleLoader(rules_dir=rule_dir)
        self.rule_engine = RuleEngine()
        self.report_generator = ReportGenerator()

        # LLM client (None if disabled or misconfigured)
        self.llm_client: Optional[LLMClient] = None
        try:
            llm_config = load_llm_config(config_dir=config_dir)
            self.llm_client = LLMClientFactory.create(llm_config)
        except Exception:
            logger.exception(
                "Failed to initialise LLM client; LLM judgment disabled."
            )
            self.llm_client = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, task: Task) -> None:
        """Orchestrate the full verification pipeline for *task*.

        Wraps the internal pipeline in ``asyncio.wait_for`` to enforce
        the configured task timeout.  Handles every exception type so
        the worker never crashes.

        Args:
            task: The verification task to execute.
        """
        try:
            await asyncio.wait_for(
                self._pipeline(task),
                timeout=self._settings.task_timeout,
            )
            # Pipeline completed (possibly with a FAIL verdict) without
            # raising an exception -- mark the task as successfully
            # processed.
            task.status = TaskStatus.SUCCESS

        except asyncio.TimeoutError:
            logger.error(
                "Task %s timed out after %d seconds.",
                task.id,
                self._settings.task_timeout,
            )
            task.status = TaskStatus.TIMEOUT
            if task.result is None:
                task.result = TaskResult(final_verdict="UNDETERMINED")

        except Exception:
            logger.exception(
                "Task %s failed with an unexpected error.", task.id
            )
            task.status = TaskStatus.FAILED
            if task.result is None:
                task.result = TaskResult(final_verdict="FAIL")

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    async def _pipeline(self, task: Task) -> None:
        """Execute all verification stages for *task*.

        Every stage is wrapped in its own try/except so a failure in any
        single stage does not prevent later stages from running.  The
        method sets ``task.result`` and returns normally on success, or
        sets ``task.result`` with ``final_verdict="FAIL"`` and returns
        normally on handled errors.  Only truly unexpected bugs (e.g.
        ``AttributeError``) are allowed to propagate to the caller.
        """
        # Initialise accumulator variables so they are always defined
        # even if a stage fails partway through.
        exp_result: Optional[ExpResult] = None
        ssh_checks: list[SSHCheck] = []
        evidence: list[dict] = []
        rules: dict[str, Any] = {}
        rule_score: Optional[RuleScore] = None
        llm_judgment: Optional[LLMJudgment] = None

        try:
            # ----------------------------------------------------------
            # 1. Ensure runtime image is ready
            # ----------------------------------------------------------
            logger.info("Ensuring runtime image for task %s ...", task.id)
            image_ready = await self.sandbox_executor.ensure_image()
            if not image_ready:
                logger.error(
                    "Runtime image could not be prepared for task %s.",
                    task.id,
                )
                task.result = TaskResult(final_verdict="FAIL")
                return

            # ----------------------------------------------------------
            # 2. Execute exploit in sandbox
            # ----------------------------------------------------------
            execute_cmd: str = task.request.get("execute_cmd", "")
            logger.info(
                "Executing EXP for task %s: %s", task.id, execute_cmd
            )
            exp_result = await self.sandbox_executor.execute(
                task.file_path, execute_cmd
            )
            logger.info(
                "EXP execution completed for task %s: "
                "exit_code=%d duration=%.2fs",
                task.id,
                exp_result.exit_code,
                exp_result.duration,
            )

            # ----------------------------------------------------------
            # 3. Build target info and select verification backend
            # ----------------------------------------------------------
            target_ip: str = task.request.get("target_ip", "")
            target_port: int = int(
                task.request.get("target_port", 22)
            )
            ssh_user: str = task.request.get("ssh_user", "root")
            ssh_password: Optional[str] = task.request.get(
                "ssh_password"
            )
            ssh_key: Optional[str] = task.request.get("ssh_key")
            verify_type: str = task.request.get("verify_type", "")
            verify_backend: str = task.request.get("verify_backend", "ssh")
            container_name: Optional[str] = task.request.get(
                "container_name"
            )

            backend: Optional[VerificationBackend] = None
            try:
                backend = get_backend(verify_backend)
            except ValueError as exc:
                logger.warning(
                    "Unknown backend '%s' for task %s: %s. "
                    "Falling back to SSH.",
                    verify_backend,
                    task.id,
                    exc,
                )
                backend = get_backend("ssh")

            # ----------------------------------------------------------
            # 4. Build target dict and connect via selected backend
            # ----------------------------------------------------------
            target: dict = {
                "host": target_ip,
                "port": target_port,
                "username": ssh_user,
            }
            if ssh_password:
                target["password"] = ssh_password
            if ssh_key:
                target["ssh_key"] = ssh_key
            if container_name:
                target["container_name"] = container_name

            session = None
            try:
                logger.info(
                    "Connecting via backend '%s' to %s:%d ...",
                    verify_backend,
                    target_ip,
                    target_port,
                )
                session = await backend.connect(target)

                logger.info(
                    "Running verification (type=%s, backend=%s) "
                    "for task %s ...",
                    verify_type,
                    verify_backend,
                    task.id,
                )
                # Pass target_ip/port as evidence for auth_bypass verifier
                verification_evidence = {
                    "target_ip": target_ip,
                    "target_port": target_port,
                }
                ssh_checks = await backend.verify(
                    session, verify_type, verification_evidence
                )
                logger.info(
                    "Verification complete for task %s (%s backend): "
                    "%d/%d checks passed",
                    task.id,
                    verify_backend,
                    sum(1 for c in ssh_checks if c.passed),
                    len(ssh_checks),
                )

            except Exception:
                logger.warning(
                    "Verification (backend=%s) failed for task %s:",
                    verify_backend,
                    task.id,
                    exc_info=True,
                )
            finally:
                if session is not None:
                    try:
                        await backend.disconnect(session)
                    except Exception:
                        logger.debug(
                            "Error disconnecting session for task %s:",
                            task.id,
                            exc_info=True,
                        )

            # ----------------------------------------------------------
            # 5. Build structured evidence
            # ----------------------------------------------------------
            logger.info("Building evidence for task %s ...", task.id)
            evidence = await self.evidence_builder.build(
                exp_result=exp_result,
                ssh_checks=ssh_checks,
                verify_type=verify_type,
                task_request=task.request,
            )

            # ----------------------------------------------------------
            # 6. Load verification rules
            # ----------------------------------------------------------
            logger.info(
                "Loading rules (type=%s) for task %s ...",
                verify_type,
                task.id,
            )
            try:
                rules = self.rule_loader.load_rules(verify_type)
            except FileNotFoundError:
                logger.warning(
                    "No rule file found for verify_type=%s "
                    "(task %s). Using empty rules.",
                    verify_type,
                    task.id,
                )
                rules = {"checks": [], "logic": {"operator": "AND"}}

            # ----------------------------------------------------------
            # 7. Evaluate rules against evidence
            # ----------------------------------------------------------
            logger.info("Evaluating rules for task %s ...", task.id)
            rule_score = self.rule_engine.evaluate(evidence, rules)

            # ----------------------------------------------------------
            # 8. LLM judgment (if client is available)
            # ----------------------------------------------------------
            if self.llm_client is not None:
                logger.info(
                    "Requesting LLM judgment for task %s ...", task.id
                )
                try:
                    summary = self.evidence_builder.build_summary(
                        evidence, exp_result, ssh_checks
                    )
                    llm_judgment = await self.llm_client.judge(summary)
                    logger.info(
                        "LLM judgment for task %s: success=%s "
                        "confidence=%.4f",
                        task.id,
                        llm_judgment.success,
                        llm_judgment.confidence,
                    )
                except Exception:
                    logger.warning(
                        "LLM judgment failed for task %s:",
                        task.id,
                        exc_info=True,
                    )

            # ----------------------------------------------------------
            # 9. Determine final verdict
            # ----------------------------------------------------------
            final_verdict = self._determine_verdict(
                rule_score=rule_score,
                exp_result=exp_result,
                ssh_checks=ssh_checks,
                llm_judgment=llm_judgment,
            )

            # ----------------------------------------------------------
            # 10. Build TaskResult
            # ----------------------------------------------------------
            task_result = TaskResult(
                exp_result=exp_result,
                ssh_checks=ssh_checks,
                evidence=evidence,
                rule_score=rule_score,
                llm_judgment=llm_judgment,
                final_verdict=final_verdict,
            )

            # ----------------------------------------------------------
            # 11. Generate reports
            # ----------------------------------------------------------
            logger.info("Generating reports for task %s ...", task.id)
            task_result.report_json = (
                self.report_generator.generate_json(task_result)
            )
            task_result.report_md = (
                self.report_generator.generate_markdown(task_result)
            )

            task.result = task_result
            logger.info(
                "Pipeline complete for task %s: final_verdict=%s",
                task.id,
                final_verdict,
            )

        except Exception:
            logger.exception(
                "Internal pipeline error for task %s.", task.id
            )
            task.result = TaskResult(
                exp_result=exp_result,
                ssh_checks=ssh_checks,
                evidence=evidence,
                rule_score=rule_score,
                llm_judgment=llm_judgment,
                final_verdict="FAIL",
            )

    # ------------------------------------------------------------------
    # Verdict logic
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_verdict(
        rule_score: Optional[RuleScore],
        exp_result: Optional[ExpResult],
        ssh_checks: list[SSHCheck],
        llm_judgment: Optional[LLMJudgment],
    ) -> str:
        """Determine the final verdict based on all pipeline results.

        Resolution order:
        1. If the rule engine says ``passed`` -> ``"SUCCESS"``
        2. Elif EXP exited with code 0 *and* at least one SSH check
           passed -> ``"SUCCESS"``
        3. Elif LLM judgment is available and says ``success`` ->
           ``"SUCCESS"``
        4. Otherwise -> ``"FAIL"``

        Returns:
            One of ``"SUCCESS"`` or ``"FAIL"``.
        """
        if rule_score is not None and rule_score.passed:
            logger.debug(
                "Verdict: SUCCESS (rule engine passed, score=%.4f)",
                rule_score.score,
            )
            return "SUCCESS"

        if (
            exp_result is not None
            and exp_result.exit_code == 0
            and any(c.passed for c in ssh_checks)
        ):
            logger.debug(
                "Verdict: SUCCESS (exit_code=0 and SSH checks passed)"
            )
            return "SUCCESS"

        if (
            llm_judgment is not None
            and llm_judgment.success
        ):
            logger.debug(
                "Verdict: SUCCESS (LLM judgment: confidence=%.4f)",
                llm_judgment.confidence,
            )
            return "SUCCESS"

        logger.debug("Verdict: FAIL (no success condition met)")
        return "FAIL"
