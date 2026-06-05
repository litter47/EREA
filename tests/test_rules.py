"""Tests for RuleLoader (YAML file loading) and RuleEngine (evidence evaluation).

Loads real YAML rule files from the project's config/rules directory
so that structural changes to the rule files are caught by CI.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import yaml

from eva_agent.rules.engine import RuleEngine
from eva_agent.rules.loader import RuleLoader
from eva_agent.task.models import ExpResult, RuleScore, SSHCheck


# ========================================================================
# RuleLoader tests
# ========================================================================


class TestRuleLoader:
    """Verify that RuleLoader correctly reads YAML rule definitions."""

    def _make_loader(self, rules_dir: str) -> RuleLoader:
        return RuleLoader(rules_dir=rules_dir)

    def test_load_rce_rules(self, rules_dir: str):
        """Load rules/rce.yaml and verify its structure."""
        loader = self._make_loader(rules_dir)
        rules = loader.load_rules("rce")

        assert isinstance(rules, dict)
        assert rules["verify_type"] == "rce"
        assert "checks" in rules
        assert "logic" in rules
        assert isinstance(rules["checks"], list)
        assert len(rules["checks"]) > 0
        assert rules["logic"]["operator"] == "AND"

    def test_load_info_leak_rules(self, rules_dir: str):
        """Load rules/info_leak.yaml and verify its structure."""
        loader = self._make_loader(rules_dir)
        rules = loader.load_rules("info_leak")

        assert isinstance(rules, dict)
        assert rules["verify_type"] == "info_leak"
        assert "checks" in rules
        assert len(rules["checks"]) == 3

    def test_load_priv_esc_rules(self, rules_dir: str):
        """Load rules/priv_esc.yaml and verify its structure."""
        loader = self._make_loader(rules_dir)
        rules = loader.load_rules("priv_esc")

        assert isinstance(rules, dict)
        assert rules["verify_type"] == "priv_esc"
        assert "checks" in rules
        assert len(rules["checks"]) == 4

    def test_load_auth_bypass_rules(self, rules_dir: str):
        """Load rules/auth_bypass.yaml and verify its structure."""
        loader = self._make_loader(rules_dir)
        rules = loader.load_rules("auth_bypass")

        assert isinstance(rules, dict)
        assert rules["verify_type"] == "auth_bypass"
        assert "checks" in rules
        assert len(rules["checks"]) == 3

    def test_load_nonexistent_rule_type(self, rules_dir: str):
        """Loading a non-existent rule file raises FileNotFoundError."""
        loader = self._make_loader(rules_dir)
        with pytest.raises(FileNotFoundError):
            loader.load_rules("nonexistent_rule_type_xyz")

    def test_list_rules(self, rules_dir: str):
        """list_rules returns expected rule names."""
        loader = self._make_loader(rules_dir)
        rule_names = loader.list_rules()

        assert isinstance(rule_names, list)
        assert "rce" in rule_names
        assert "info_leak" in rule_names
        assert "priv_esc" in rule_names
        assert "auth_bypass" in rule_names


# ========================================================================
# RuleEngine tests
# ========================================================================


class _EvidenceFactory:
    """Helper to build evidence dicts for rule engine tests."""

    @staticmethod
    def make_exp_execution(
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        duration: float = 1.0,
    ) -> dict:
        return {
            "type": "exp_execution",
            "source": "sandbox",
            "data": {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "duration": duration,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def make_ssh_check(
        check_name: str, passed: bool, details: str = ""
    ) -> dict:
        return {
            "type": "ssh_verification",
            "source": "ssh",
            "data": {
                "check_name": check_name,
                "passed": passed,
                "details": details,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class TestRuleEngine:
    """Verify the RuleEngine evaluation logic."""

    def setup_method(self) -> None:
        self.engine = RuleEngine()

    # ------------------------------------------------------------------
    # Full evaluation (multiple checks, AND / OR logic)
    # ------------------------------------------------------------------

    def test_engine_evaluate_all_pass(self):
        """All checks pass -> score=1.0, passed=True."""
        evidence = [
            _EvidenceFactory.make_exp_execution(exit_code=0),
            _EvidenceFactory.make_ssh_check("port_open", passed=True),
        ]
        rules = {
            "checks": [
                {
                    "name": "exit_ok",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
                {
                    "name": "port_open",
                    "type": "ssh_check",
                    "params": {"check_name": "port_open"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result: RuleScore = self.engine.evaluate(evidence, rules)

        assert result.score == 1.0
        assert result.passed is True
        assert sorted(result.matched_rules) == ["exit_ok", "port_open"]

    def test_engine_evaluate_all_fail(self):
        """All checks fail -> score=0.0, passed=False."""
        evidence = [
            _EvidenceFactory.make_exp_execution(exit_code=1),
            _EvidenceFactory.make_ssh_check("port_open", passed=False),
        ]
        rules = {
            "checks": [
                {
                    "name": "exit_ok",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
                {
                    "name": "port_open",
                    "type": "ssh_check",
                    "params": {"check_name": "port_open"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result: RuleScore = self.engine.evaluate(evidence, rules)

        assert result.score == 0.0
        assert result.passed is False
        assert result.matched_rules == []

    def test_engine_evaluate_partial_pass(self):
        """Some checks pass -> 0 < score < 1.0, all checks must pass for AND."""
        evidence = [
            _EvidenceFactory.make_exp_execution(exit_code=0),
            _EvidenceFactory.make_ssh_check("port_open", passed=False),
        ]
        rules = {
            "checks": [
                {
                    "name": "exit_ok",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
                {
                    "name": "port_open",
                    "type": "ssh_check",
                    "params": {"check_name": "port_open"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result: RuleScore = self.engine.evaluate(evidence, rules)

        # 1 check passed out of 2 => 1.0 / 2.0 = 0.5
        assert result.score == 0.5
        # AND logic: not all passed => passed=False
        assert result.passed is False
        assert result.matched_rules == ["exit_ok"]

    # ------------------------------------------------------------------
    # Logic operators
    # ------------------------------------------------------------------

    def test_engine_and_logic(self):
        """AND logic: all checks must pass for overall pass."""
        evidence = [
            _EvidenceFactory.make_exp_execution(exit_code=0),
            _EvidenceFactory.make_ssh_check("check_a", passed=True),
            _EvidenceFactory.make_ssh_check("check_b", passed=False),
        ]
        rules = {
            "checks": [
                {
                    "name": "chk_exit",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
                {
                    "name": "chk_a",
                    "type": "ssh_check",
                    "params": {"check_name": "check_a"},
                    "weight": 1.0,
                },
                {
                    "name": "chk_b",
                    "type": "ssh_check",
                    "params": {"check_name": "check_b"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result = self.engine.evaluate(evidence, rules)

        # 2 of 3 passed, but AND requires ALL => passed=False
        assert result.passed is False

    def test_engine_or_logic(self):
        """OR logic: at least one check must pass for overall pass."""
        evidence = [
            _EvidenceFactory.make_exp_execution(exit_code=0),
            _EvidenceFactory.make_ssh_check("check_a", passed=False),
        ]
        rules = {
            "checks": [
                {
                    "name": "chk_exit",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
                {
                    "name": "chk_a",
                    "type": "ssh_check",
                    "params": {"check_name": "check_a"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "OR"},
        }

        result = self.engine.evaluate(evidence, rules)

        # chk_exit passed (exit_code==0), chk_a failed => OR => passed=True
        assert result.passed is True
        assert result.score == 0.5

    # ------------------------------------------------------------------
    # Individual check types
    # ------------------------------------------------------------------

    def test_engine_exit_code_check(self):
        """exit_code check: matches expected value."""
        # Exit code matches expected 0
        evidence_pass = [_EvidenceFactory.make_exp_execution(exit_code=0)]
        # Exit code does not match expected 0
        evidence_fail = [_EvidenceFactory.make_exp_execution(exit_code=1)]

        rules = {
            "checks": [
                {
                    "name": "exit_ok",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result_pass = self.engine.evaluate(evidence_pass, rules)
        result_fail = self.engine.evaluate(evidence_fail, rules)

        assert result_pass.passed is True
        assert result_fail.passed is False

    def test_engine_ssh_check(self):
        """ssh_check: checks whether a named SSH check passed."""
        evidence = [
            _EvidenceFactory.make_ssh_check("file_check", passed=True),
            _EvidenceFactory.make_ssh_check("port_check", passed=False),
        ]

        rules = {
            "checks": [
                {
                    "name": "file_check",
                    "type": "ssh_check",
                    "params": {"check_name": "file_check"},
                    "weight": 1.0,
                },
                {
                    "name": "port_check",
                    "type": "ssh_check",
                    "params": {"check_name": "port_check"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result = self.engine.evaluate(evidence, rules)

        assert result.passed is False  # port_check failed
        assert "file_check" in result.matched_rules
        assert "port_check" not in result.matched_rules

    def test_engine_content_match(self):
        """content_match: searches stdout/stderr for expected patterns."""
        evidence = [
            _EvidenceFactory.make_exp_execution(
                stdout="exploit successfully completed\nshell obtained",
                stderr="",
                exit_code=0,
            ),
        ]

        rules = {
            "checks": [
                {
                    "name": "found_exploit_msg",
                    "type": "content_match",
                    "params": {"patterns": ["exploit succeeded", "shell obtained"]},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "OR"},
        }

        result = self.engine.evaluate(evidence, rules)

        # "shell obtained" should match (case-insensitive)
        assert result.passed is True
        assert result.score > 0.0

    def test_engine_content_match_no_match(self):
        """content_match: no patterns found in output -> fail."""
        evidence = [
            _EvidenceFactory.make_exp_execution(
                stdout="some unrelated output",
                stderr="",
                exit_code=1,
            ),
        ]

        rules = {
            "checks": [
                {
                    "name": "found_exploit_msg",
                    "type": "content_match",
                    "params": {"patterns": ["exploit succeeded", "shell obtained"]},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result = self.engine.evaluate(evidence, rules)

        assert result.passed is False
        assert result.score == 0.0

    def test_engine_content_regex(self):
        """content_regex: searches stdout/stderr with a regex."""
        evidence = [
            _EvidenceFactory.make_exp_execution(
                stdout="uid=0(root) gid=0(root)",
                stderr="",
                exit_code=0,
            ),
        ]
        rules = {
            "checks": [
                {
                    "name": "id_output",
                    "type": "content_regex",
                    "params": {
                        "patterns": [
                            r"uid=[0-9]+\([^)]*\).*gid=[0-9]+\([^)]*\)"
                        ]
                    },
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND"},
        }

        result = self.engine.evaluate(evidence, rules)

        assert result.passed is True
        assert result.matched_rules == ["id_output"]

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    def test_engine_empty_checks(self):
        """No checks defined -> score=0.0, passed=False, empty matched_rules."""
        evidence = [_EvidenceFactory.make_exp_execution(exit_code=0)]

        rules = {
            "checks": [],
            "logic": {"operator": "AND"},
        }

        result = self.engine.evaluate(evidence, rules)

        assert result.score == 0.0
        assert result.passed is False
        assert result.matched_rules == []

    def test_engine_missing_checks_key(self):
        """Rules dict with no 'checks' key -> treated as empty (graceful)."""
        evidence = [_EvidenceFactory.make_exp_execution(exit_code=0)]

        rules = {"logic": {"operator": "AND"}}

        result = self.engine.evaluate(evidence, rules)

        assert result.score == 0.0
        assert result.passed is False

    def test_engine_threshold_override(self):
        """Threshold overrides AND logic when score meets threshold."""
        evidence = [
            _EvidenceFactory.make_exp_execution(exit_code=0),
            _EvidenceFactory.make_ssh_check("check_a", passed=False),
        ]
        rules = {
            "checks": [
                {
                    "name": "exit_ok",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
                {
                    "name": "check_a",
                    "type": "ssh_check",
                    "params": {"check_name": "check_a"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND", "threshold": 0.4},
        }

        result = self.engine.evaluate(evidence, rules)

        # score = 0.5 (1/2 passed), threshold = 0.4 => passed
        assert result.score == 0.5
        assert result.passed is True

    def test_engine_threshold_not_met(self):
        """Threshold not met -> passed=False even if AND logic passes partially."""
        evidence = [
            _EvidenceFactory.make_exp_execution(exit_code=0),
            _EvidenceFactory.make_ssh_check("check_a", passed=False),
        ]
        rules = {
            "checks": [
                {
                    "name": "exit_ok",
                    "type": "exit_code",
                    "params": {"expected": 0},
                    "weight": 1.0,
                },
                {
                    "name": "check_a",
                    "type": "ssh_check",
                    "params": {"check_name": "check_a"},
                    "weight": 1.0,
                },
            ],
            "logic": {"operator": "AND", "threshold": 0.8},
        }

        result = self.engine.evaluate(evidence, rules)

        # score = 0.5, threshold = 0.8 => not met
        assert result.score == 0.5
        assert result.passed is False
