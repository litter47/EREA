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
import shlex
from typing import Any, Optional

from eva_agent.config.settings import Settings
from eva_agent.evidence.builder import EvidenceBuilder
from eva_agent.llm.client import LLMClient
from eva_agent.llm.config import load_llm_config
from eva_agent.llm.factory import LLMClientFactory
from eva_agent.report.generator import ReportGenerator
from eva_agent.rules.dynamic import normalize_generated_rules
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
        using_generated_rules = False

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
            source_language: Optional[str] = task.request.get("source_language")
            logger.info(
                "Executing EXP for task %s: %s", task.id, execute_cmd
            )
            exp_result = await self.sandbox_executor.execute(
                task.file_path,
                execute_cmd,
                source_language=source_language,
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
            generate_rules_with_llm = bool(
                task.request.get("generate_rules_with_llm", False)
            )

            # ----------------------------------------------------------
            # 4. Generate or load verification rules
            # ----------------------------------------------------------
            if generate_rules_with_llm:
                rules = await self._generate_rules_with_llm(
                    task=task,
                    verify_type=verify_type,
                )
                using_generated_rules = bool(rules.get("checks"))

            if not using_generated_rules:
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
            # 5. Build target dict and connect via selected backend
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
                if using_generated_rules:
                    ssh_checks = []
                else:
                    # Pass target_ip/port as evidence for auth_bypass verifier
                    verification_evidence = {
                        "target_ip": target_ip,
                        "target_port": target_port,
                    }
                    ssh_checks = await backend.verify(
                        session, verify_type, verification_evidence
                    )
                generated_probe_checks = await self._run_generated_probes(
                    backend=backend,
                    session=session,
                    rules=rules,
                    target_ip=target_ip,
                    target_port=target_port,
                )
                if generated_probe_checks:
                    ssh_checks.extend(generated_probe_checks)
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
            # 6. Build structured evidence
            # ----------------------------------------------------------
            logger.info("Building evidence for task %s ...", task.id)
            evidence = await self.evidence_builder.build(
                exp_result=exp_result,
                ssh_checks=ssh_checks,
                verify_type=verify_type,
                task_request=task.request,
            )

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
                strict_rule_verdict=using_generated_rules,
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
        strict_rule_verdict: bool = False,
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

        if strict_rule_verdict:
            logger.debug("Verdict: FAIL (generated rules did not pass)")
            return "FAIL"

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

    async def _generate_rules_with_llm(
        self,
        task: Task,
        verify_type: str,
    ) -> dict[str, Any]:
        """Generate a constrained rule set with the configured LLM."""
        if self.llm_client is None:
            logger.warning(
                "Task %s requested LLM rule generation, but no LLM client "
                "is configured. Falling back to YAML rules.",
                task.id,
            )
            return {"checks": [], "logic": {"operator": "AND"}}

        exploit_content = self._read_exploit_text(task.file_path)
        task_context = {
            "verify_type": verify_type,
            "execute_cmd": task.request.get("execute_cmd", ""),
            "target_ip": task.request.get("target_ip", ""),
            "target_port": task.request.get("target_port", 0),
            "source_language": task.request.get("source_language"),
            "original_filename": task.request.get("original_filename"),
        }

        try:
            raw_rules = await self.llm_client.generate_rules(
                task_context=task_context,
                exploit_content=exploit_content,
            )
        except Exception:
            logger.warning(
                "LLM rule generation failed for task %s; falling back to YAML.",
                task.id,
                exc_info=True,
            )
            return {"checks": [], "logic": {"operator": "AND"}}

        rules = normalize_generated_rules(raw_rules, verify_type=verify_type)
        logger.info(
            "Generated %d constrained rule check(s) for task %s",
            len(rules.get("checks", [])),
            task.id,
        )
        return rules

    @staticmethod
    def _read_exploit_text(file_path: str, limit: int = 12000) -> str:
        """Read uploaded exploit text for rule planning, best effort."""
        try:
            with open(file_path, "rb") as fh:
                data = fh.read(limit)
        except OSError:
            return ""
        return data.decode("utf-8", errors="replace")

    async def _run_generated_probes(
        self,
        backend: VerificationBackend,
        session: Any,
        rules: dict[str, Any],
        target_ip: str = "",
        target_port: int = 80,
    ) -> list[SSHCheck]:
        """Run dynamic probes embedded in generated rules."""
        checks: list[SSHCheck] = []
        for check in rules.get("checks", []):
            if not isinstance(check, dict):
                continue
            probe = check.get("probe")
            if not isinstance(probe, dict):
                continue

            check_name = str(
                probe.get(
                    "check_name",
                    check.get("params", {}).get(
                        "check_name", check.get("name", "generated_probe")
                    ),
                )
            )
            result = await self._run_single_probe(
                backend=backend,
                session=session,
                check_name=check_name,
                probe=probe,
                target_ip=target_ip,
                target_port=target_port,
            )
            checks.append(result)
        return checks

    async def _run_single_probe(
        self,
        backend: VerificationBackend,
        session: Any,
        check_name: str,
        probe: dict[str, Any],
        target_ip: str = "",
        target_port: int = 80,
    ) -> SSHCheck:
        probe_type = str(probe.get("type", "")).lower()

        if backend.backend_type == "http" and probe_type not in {
            "http_body_contains",
            "http_status",
        }:
            return SSHCheck(
                check_name=check_name,
                passed=False,
                details=f"Probe type '{probe_type}' requires command execution.",
            )

        if probe_type == "file_exists":
            path = str(probe.get("path", ""))
            cmd = f"test -f {shlex.quote(path)}"
            stdout, stderr, exit_code = await backend.run(session, cmd)
            passed = exit_code == 0
            details = (
                f"File exists: {path}"
                if passed
                else f"File not found: {path}. {stderr or stdout}".strip()
            )
            return SSHCheck(check_name=check_name, passed=passed, details=details)

        if probe_type == "file_contains":
            path = str(probe.get("path", ""))
            pattern = str(probe.get("pattern", ""))
            cmd = (
                f"grep -F -- {shlex.quote(pattern)} "
                f"{shlex.quote(path)} >/dev/null 2>&1"
            )
            stdout, stderr, exit_code = await backend.run(session, cmd)
            passed = exit_code == 0
            details = (
                f"File {path} contains expected pattern."
                if passed
                else f"Pattern not found in {path}. {stderr or stdout}".strip()
            )
            return SSHCheck(check_name=check_name, passed=passed, details=details)

        if probe_type == "port_listening":
            port = int(probe.get("port"))
            cmd = (
                "ss -tln | awk '{print $4}' | "
                f"grep -E '(^|:){port}$' >/dev/null 2>&1"
            )
            stdout, stderr, exit_code = await backend.run(session, cmd)
            passed = exit_code == 0
            details = (
                f"Port {port} is listening."
                if passed
                else f"Port {port} is not listening. {stderr or stdout}".strip()
            )
            return SSHCheck(check_name=check_name, passed=passed, details=details)

        if probe_type == "http_body_contains":
            path = str(probe.get("path", "/"))
            pattern = str(probe.get("pattern", ""))
            body, status_code, error = await self._fetch_http_probe(
                target_ip=target_ip,
                target_port=target_port,
                path=path,
            )
            passed = error == "" and pattern in body
            details = (
                f"HTTP response contains expected pattern at {path}."
                if passed
                else f"HTTP response did not contain expected pattern at {path}. {error}".strip()
            )
            return SSHCheck(check_name=check_name, passed=passed, details=details)

        if probe_type == "http_status":
            path = str(probe.get("path", "/"))
            expected_status = int(probe.get("status", 200))
            _body, status_code, error = await self._fetch_http_probe(
                target_ip=target_ip,
                target_port=target_port,
                path=path,
            )
            passed = error == "" and status_code == expected_status
            details = (
                f"HTTP status matched {expected_status} at {path}."
                if passed
                else (
                    f"HTTP status did not match {expected_status} at {path}. "
                    f"actual={status_code} {error}"
                ).strip()
            )
            return SSHCheck(check_name=check_name, passed=passed, details=details)

        return SSHCheck(
            check_name=check_name,
            passed=False,
            details=f"Unsupported generated probe type: {probe_type}",
        )

    @staticmethod
    async def _fetch_http_probe(
        target_ip: str,
        target_port: int,
        path: str,
    ) -> tuple[str, int, str]:
        import httpx

        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = f"http://{target_ip}:{target_port}{path}"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, follow_redirects=True)
        except Exception as exc:
            return "", 0, str(exc)

        return response.text, response.status_code, ""
