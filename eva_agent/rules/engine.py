"""Rule engine that evaluates a set of verification rules against
collected evidence and produces a ``RuleScore``.
"""

from __future__ import annotations

import logging
from typing import Any

from eva_agent.task.models import RuleScore

logger = logging.getLogger(__name__)

_CHECK_TYPES = frozenset({"exit_code", "ssh_check", "content_match"})


class RuleEngine:
    """Evaluates structured evidence against YAML-defined verification rules.

    Expected rules structure (YAML)::

        checks:
          - name: check_exit_code
            type: exit_code
            params:
              expected: 0
            weight: 1.0
          - name: check_port_closed
            type: ssh_check
            params:
              check_name: port_80_closed
            weight: 2.0
          - name: check_log_content
            type: content_match
            params:
              patterns:
                - "exploit succeeded"
                - "shell obtained"
            weight: 1.0
        logic:
          operator: AND        # AND | OR
          threshold: 0.5       # optional minimum score for passing
    """

    @staticmethod
    def _find_evidence_item(
        evidence: list[dict], check_type: str, check_name: str
    ) -> dict | None:
        """Locate the first evidence dict matching *check_type* and optionally
        *check_name* (for ssh_verification items)."""
        for item in evidence:
            if item.get("type") != check_type:
                continue
            if check_type == "ssh_verification":
                data = item.get("data", {})
                if data.get("check_name") == check_name:
                    return item
            else:
                return item
        return None

    @staticmethod
    def _evaluate_exit_code(item: dict, params: dict) -> bool:
        """Check if the EXP exit code matches the expected value."""
        expected = params.get("expected", 0)
        actual = item.get("data", {}).get("exit_code")
        passed = actual == expected
        logger.debug(
            "exit_code check: expected=%s actual=%s -> %s",
            expected,
            actual,
            passed,
        )
        return passed

    @staticmethod
    def _evaluate_ssh_check(item: dict, params: dict) -> bool:
        """Check whether a named SSH check passed."""
        passed = item.get("data", {}).get("passed", False)
        logger.debug(
            "ssh_check '%s': passed=%s",
            params.get("check_name", "unknown"),
            passed,
        )
        return bool(passed)

    @staticmethod
    def _evaluate_content_match(evidence: list[dict], params: dict) -> bool:
        """Search stdout/stderr for expected patterns."""
        patterns: list[str] = params.get("patterns", [])
        if not patterns:
            logger.warning("content_match check has no patterns to search")
            return False

        # Collect all text from exp_execution evidence
        texts: list[str] = []
        for item in evidence:
            if item.get("type") == "exp_execution":
                data = item.get("data", {})
                texts.append(data.get("stdout", ""))
                texts.append(data.get("stderr", ""))

        combined = "\n".join(texts).lower()
        for pattern in patterns:
            if pattern.lower() in combined:
                logger.debug("content_match found pattern: %s", pattern)
                return True

        logger.debug(
            "content_match: none of %d patterns found", len(patterns)
        )
        return False

    def evaluate(
        self, evidence: list[dict], rules: dict[str, Any]
    ) -> RuleScore:
        """Evaluate evidence against the provided rule definitions.

        Args:
            evidence: List of evidence dicts as produced by
                ``EvidenceBuilder.build()``.
            rules: Parsed YAML dict with top-level keys ``checks`` and
                ``logic``.

        Returns:
            A ``RuleScore`` with score (0.0-1.0), passed (bool), and
            matched_rules (list of check names that passed).
        """
        checks: list[dict] = rules.get("checks", [])
        logic: dict = rules.get("logic", {"operator": "AND"})

        if not checks:
            logger.warning("No checks defined in rules")
            return RuleScore(score=0.0, passed=False, matched_rules=[])

        operator = logic.get("operator", "AND").upper()
        threshold = logic.get("threshold", None)

        results: list[tuple[str, bool, float]] = []  # (name, passed, weight)
        total_weight = 0.0

        for check in checks:
            name: str = check.get("name", "unnamed_check")
            check_type: str = check.get("type", "")
            params: dict = check.get("params", {})
            weight: float = float(check.get("weight", 1.0))

            if check_type not in _CHECK_TYPES:
                logger.warning(
                    "Unknown check type '%s' in check '%s', skipping",
                    check_type,
                    name,
                )
                continue

            passed = False

            if check_type == "exit_code":
                item = self._find_evidence_item(
                    evidence, "exp_execution", name
                )
                if item:
                    passed = self._evaluate_exit_code(item, params)

            elif check_type == "ssh_check":
                check_name_param = params.get("check_name", name)
                item = self._find_evidence_item(
                    evidence, "ssh_verification", check_name_param
                )
                if item:
                    passed = self._evaluate_ssh_check(item, params)
                else:
                    logger.warning(
                        "No ssh_verification evidence found for '%s'",
                        check_name_param,
                    )

            elif check_type == "content_match":
                passed = self._evaluate_content_match(evidence, params)

            results.append((name, passed, weight))
            total_weight += weight

        # Compute weighted score
        passed_weight = sum(w for _, p, w in results if p)
        score = passed_weight / total_weight if total_weight > 0 else 0.0

        # Determine overall pass/fail based on logic operator
        if operator == "AND":
            all_passed = all(p for _, p, _ in results)
            overall_passed = all_passed
        elif operator == "OR":
            any_passed = any(p for _, p, _ in results)
            overall_passed = any_passed
        else:
            logger.warning(
                "Unknown logic operator '%s', defaulting to AND", operator
            )
            overall_passed = all(p for _, p, _ in results)

        # If threshold is specified, it can override the pass/fail
        if threshold is not None and isinstance(threshold, (int, float)):
            overall_passed = score >= float(threshold)

        matched_rules = [name for name, p, _ in results if p]

        rule_score = RuleScore(
            score=round(score, 4),
            passed=overall_passed,
            matched_rules=matched_rules,
        )

        logger.info(
            "RuleEngine result: score=%.4f passed=%s matched=%d/%d",
            rule_score.score,
            rule_score.passed,
            len(matched_rules),
            len(checks),
        )
        return rule_score
