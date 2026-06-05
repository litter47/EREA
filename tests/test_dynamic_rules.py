"""Tests for constrained LLM-generated rule normalisation."""

from __future__ import annotations

from eva_agent.rules.dynamic import normalize_generated_rules


def test_normalize_file_exists_probe() -> None:
    raw = {
        "logic": {"operator": "AND"},
        "checks": [
            {
                "name": "created_marker",
                "type": "file_exists",
                "path": "/a/b/c",
            }
        ],
    }

    rules = normalize_generated_rules(raw, verify_type="rce")

    assert rules["logic"]["operator"] == "AND"
    assert rules["checks"][0]["type"] == "ssh_check"
    assert rules["checks"][0]["params"]["check_name"] == "generated_file_exists_0"
    assert rules["checks"][0]["probe"]["path"] == "/a/b/c"


def test_normalize_stdout_regex_alias() -> None:
    raw = {
        "checks": [
            {
                "type": "stdout_regex",
                "pattern": r"uid=[0-9]+",
            }
        ]
    }

    rules = normalize_generated_rules(raw, verify_type="rce")

    assert rules["checks"][0]["type"] == "content_regex"
    assert rules["checks"][0]["params"]["patterns"] == [r"uid=[0-9]+"]


def test_rejects_unsafe_file_path_probe() -> None:
    raw = {
        "checks": [
            {
                "type": "file_exists",
                "path": "relative/path",
            }
        ]
    }

    rules = normalize_generated_rules(raw, verify_type="rce")

    assert rules["checks"] == []


def test_normalize_http_body_probe() -> None:
    raw = {
        "checks": [
            {
                "type": "http_response_contains",
                "path": "/result",
                "value": "uid=0(root)",
            }
        ]
    }

    rules = normalize_generated_rules(raw, verify_type="rce")

    assert rules["checks"][0]["type"] == "ssh_check"
    assert rules["checks"][0]["probe"]["type"] == "http_body_contains"
    assert rules["checks"][0]["probe"]["pattern"] == "uid=0(root)"
