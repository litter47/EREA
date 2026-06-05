"""Tests for sandbox source build command selection."""

from __future__ import annotations

from eva_agent.sandbox.executor import SandboxExecutor


def test_c_source_build_command() -> None:
    assert (
        SandboxExecutor._build_command("c")
        == "gcc -x c /exp/exploit -o /exp/exploit_bin"
    )


def test_cpp_source_build_command() -> None:
    assert (
        SandboxExecutor._build_command("cpp")
        == "g++ -x c++ /exp/exploit -o /exp/exploit_bin"
    )


def test_auto_run_command_for_source() -> None:
    assert SandboxExecutor._run_command("auto", "c") == "/exp/exploit_bin"
    assert SandboxExecutor._run_command("", "cpp") == "/exp/exploit_bin"


def test_explicit_run_command_preserved() -> None:
    assert (
        SandboxExecutor._run_command("/exp/exploit_bin --target 1.2.3.4", "c")
        == "/exp/exploit_bin --target 1.2.3.4"
    )
