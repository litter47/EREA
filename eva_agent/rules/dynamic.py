"""Helpers for normalising LLM-generated verification rules.

The LLM is allowed to describe *what* to check, but the worker keeps
execution constrained by converting dynamic probes into ordinary
``ssh_check`` rules with a small allowlist of probe types.
"""

from __future__ import annotations

import re
from typing import Any

_DIRECT_CHECK_TYPES = {"exit_code", "ssh_check", "content_match", "content_regex"}
_PROBE_TYPES = {
    "file_exists",
    "file_contains",
    "port_listening",
    "http_body_contains",
    "http_response_contains",
    "http_status",
}


def normalize_generated_rules(
    raw_rules: dict[str, Any],
    verify_type: str,
) -> dict[str, Any]:
    """Convert model output into RuleEngine-compatible rules.

    Supported model check types:
    - exit_code, content_match, content_regex, ssh_check
    - stdout_contains (alias for content_match)
    - stdout_regex (alias for content_regex)
    - file_exists, file_contains, port_listening, http_body_contains,
      http_response_contains, http_status (executed as probes)
    """
    if not isinstance(raw_rules, dict):
        return _empty_rules(verify_type)

    logic = _normalize_logic(raw_rules.get("logic"))
    normalized: dict[str, Any] = {
        "verify_type": verify_type,
        "description": str(
            raw_rules.get("description", "LLM-generated verification rules")
        )[:500],
        "logic": logic,
        "checks": [],
    }

    checks = raw_rules.get("checks", [])
    if not isinstance(checks, list):
        return normalized

    for idx, raw_check in enumerate(checks):
        if not isinstance(raw_check, dict):
            continue

        check_type = str(raw_check.get("type", "")).strip().lower()
        params = raw_check.get("params", {})
        if not isinstance(params, dict):
            params = {}

        name = _safe_name(raw_check.get("name"), idx)
        weight = _safe_weight(raw_check.get("weight", 1.0))

        if check_type == "stdout_contains":
            pattern = _first_string(
                params.get("value"),
                params.get("pattern"),
                raw_check.get("value"),
                raw_check.get("pattern"),
            )
            if pattern:
                normalized["checks"].append(
                    {
                        "name": name,
                        "type": "content_match",
                        "params": {"patterns": [pattern]},
                        "weight": weight,
                    }
                )
            continue

        if check_type == "stdout_regex":
            pattern = _first_string(
                params.get("pattern"),
                params.get("value"),
                raw_check.get("pattern"),
                raw_check.get("value"),
            )
            if pattern:
                normalized["checks"].append(
                    {
                        "name": name,
                        "type": "content_regex",
                        "params": {"patterns": [pattern]},
                        "weight": weight,
                    }
                )
            continue

        if check_type in _DIRECT_CHECK_TYPES:
            normalized_check = {
                "name": name,
                "type": check_type,
                "params": params,
                "weight": weight,
            }
            probe = _normalize_probe(raw_check.get("probe"), idx)
            if probe is not None:
                normalized_check["probe"] = probe
            normalized["checks"].append(normalized_check)
            continue

        if check_type in _PROBE_TYPES:
            probe = _normalize_probe(
                {"type": check_type, **params, **raw_check},
                idx,
            )
            if probe is None:
                continue
            canonical_type = (
                "http_body_contains"
                if check_type == "http_response_contains"
                else check_type
            )
            check_name = f"generated_{canonical_type}_{idx}"
            normalized["checks"].append(
                {
                    "name": name,
                    "type": "ssh_check",
                    "params": {"check_name": check_name},
                    "weight": weight,
                    "probe": probe | {"check_name": check_name},
                }
            )

    return normalized


def _empty_rules(verify_type: str) -> dict[str, Any]:
    return {
        "verify_type": verify_type,
        "description": "No generated rules",
        "logic": {"operator": "AND"},
        "checks": [],
    }


def _normalize_logic(raw_logic: Any) -> dict[str, Any]:
    if not isinstance(raw_logic, dict):
        return {"operator": "AND"}

    operator = str(raw_logic.get("operator", "AND")).upper()
    if operator not in {"AND", "OR"}:
        operator = "AND"

    logic: dict[str, Any] = {"operator": operator}
    threshold = raw_logic.get("threshold")
    if isinstance(threshold, (int, float)):
        logic["threshold"] = float(threshold)
    return logic


def _safe_name(raw_name: Any, index: int) -> str:
    name = str(raw_name or f"generated_check_{index}")
    name = re.sub(r"[^A-Za-z0-9_.:-]+", "_", name).strip("_")
    return name[:80] or f"generated_check_{index}"


def _safe_weight(raw_weight: Any) -> float:
    try:
        weight = float(raw_weight)
    except (TypeError, ValueError):
        return 1.0
    if weight <= 0:
        return 1.0
    return min(weight, 10.0)


def _first_string(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value:
            return value[:500]
    return None


def _normalize_probe(raw_probe: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(raw_probe, dict):
        return None

    probe_type = str(raw_probe.get("type", "")).strip().lower()
    if probe_type not in _PROBE_TYPES:
        return None

    if probe_type in {"file_exists", "file_contains"}:
        path = _first_string(raw_probe.get("path"))
        if not _safe_remote_path(path):
            return None
        probe: dict[str, Any] = {
            "type": probe_type,
            "path": path,
            "check_name": str(
                raw_probe.get("check_name", f"generated_{probe_type}_{index}")
            )[:120],
        }
        if probe_type == "file_contains":
            pattern = _first_string(
                raw_probe.get("pattern"),
                raw_probe.get("value"),
            )
            if not pattern:
                return None
            probe["pattern"] = pattern
        return probe

    if probe_type == "http_response_contains":
        probe_type = "http_body_contains"

    if probe_type == "port_listening":
        try:
            port = int(raw_probe.get("port"))
        except (TypeError, ValueError):
            return None
        if not 1 <= port <= 65535:
            return None
        return {
            "type": probe_type,
            "port": port,
            "check_name": str(
                raw_probe.get("check_name", f"generated_{probe_type}_{index}")
            )[:120],
        }

    if probe_type in {"http_body_contains", "http_status"}:
        path = _first_string(
            raw_probe.get("path"),
            raw_probe.get("url"),
            raw_probe.get("endpoint"),
        )
        if not _safe_http_path(path):
            return None
        probe = {
            "type": probe_type,
            "path": path,
            "check_name": str(
                raw_probe.get("check_name", f"generated_{probe_type}_{index}")
            )[:120],
        }
        if probe_type == "http_body_contains":
            pattern = _first_string(
                raw_probe.get("pattern"),
                raw_probe.get("value"),
            )
            if not pattern:
                return None
            probe["pattern"] = pattern
        else:
            try:
                status = int(raw_probe.get("status", raw_probe.get("expected", 200)))
            except (TypeError, ValueError):
                return None
            if not 100 <= status <= 599:
                return None
            probe["status"] = status
        return probe

    return None


def _safe_remote_path(path: str | None) -> bool:
    if not path:
        return False
    if len(path) > 512:
        return False
    if any(ch in path for ch in ("\x00", "\n", "\r")):
        return False
    return path.startswith("/")


def _safe_http_path(path: str | None) -> bool:
    if not path:
        return False
    if len(path) > 512:
        return False
    if any(ch in path for ch in ("\x00", "\n", "\r")):
        return False
    return path.startswith("/") or path.startswith("http://") or path.startswith(
        "https://"
    )
