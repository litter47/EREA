"""Rule loader that reads verification rule definitions from YAML files.

Each rule file is named after a verify type (e.g. ``CVE-2025-1234.yaml``)
and lives under a configurable rules directory.
"""

from __future__ import annotations

import logging
import os
from glob import glob
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class RuleLoader:
    """Loads verification rule definitions from YAML files.

    Args:
        rules_dir: Absolute or relative path to the directory
            containing ``.yaml`` rule files.
    """

    def __init__(self, rules_dir: str) -> None:
        self.rules_dir = rules_dir

    def load_rules(self, verify_type: str) -> dict[str, Any]:
        """Load a rule file for the given *verify_type*.

        The file is expected at ``{rules_dir}/{verify_type}.yaml``.

        Args:
            verify_type: The verification type name which maps directly
                to a YAML filename without extension.

        Returns:
            The parsed YAML content as a Python dict.

        Raises:
            FileNotFoundError: If the YAML file does not exist.
            yaml.YAMLError: If the YAML file is malformed.
        """
        filepath = os.path.join(self.rules_dir, f"{verify_type}.yaml")
        logger.info("Loading rules from %s", filepath)

        if not os.path.isfile(filepath):
            raise FileNotFoundError(
                f"Rule file not found: {filepath} "
                f"(verify_type={verify_type})"
            )

        with open(filepath, "r", encoding="utf-8") as fh:
            rules: dict[str, Any] = yaml.safe_load(fh)

        if not isinstance(rules, dict):
            raise ValueError(
                f"Rule file {filepath} must contain a top-level mapping, "
                f"got {type(rules).__name__}"
            )

        logger.debug(
            "Loaded rules for %s: %d top-level keys",
            verify_type,
            len(rules),
        )
        return rules

    def list_rules(self) -> list[str]:
        """List available rule file names (without extensions).

        Returns:
            Sorted list of rule file stem names (e.g.
            ``["CVE-2025-1234", "CVE-2025-5678"]``).
        """
        pattern = os.path.join(self.rules_dir, "*.yaml")
        files = glob(pattern)
        stems: list[str] = sorted(
            os.path.splitext(os.path.basename(f))[0] for f in files
        )
        logger.debug("Available rule files: %s", stems)
        return stems
