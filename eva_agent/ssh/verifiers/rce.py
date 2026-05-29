"""RCE (Remote Code Execution) verifier.

Checks for signs of successful code execution on the remote host,
such as file creation, suspicious processes, new network listeners,
and recently created files in /tmp.
"""

from __future__ import annotations

from typing import Optional

from eva_agent.ssh.agent import SSHVerificationAgent
from eva_agent.task.models import SSHCheck


async def verify(
    agent: SSHVerificationAgent,
    conn: object,
    evidence: Optional[dict] = None,
) -> list[SSHCheck]:
    """Run RCE verification checks against the remote host.

    Args:
        agent: An SSHVerificationAgent instance.
        conn: An active SSHClientConnection.
        evidence: Optional contextual evidence dict (unused for RCE).

    Returns:
        A list of SSHCheck results.
    """
    results: list[SSHCheck] = []

    # ---- Check 1: file_side_effect ---------------------------------
    # Determine if /tmp/pwned exists on the remote host, which
    # typically indicates that an exploit successfully wrote a marker.
    try:
        stdout, stderr, exit_code = await agent.run(conn, "test -f /tmp/pwned")
        if exit_code == 0:
            results.append(
                SSHCheck(
                    check_name="file_side_effect",
                    passed=True,
                    details="/tmp/pwned exists on the remote host.",
                )
            )
        else:
            results.append(
                SSHCheck(
                    check_name="file_side_effect",
                    passed=False,
                    details="/tmp/pwned was not found on the remote host.",
                )
            )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="file_side_effect",
                passed=False,
                details=f"Error checking /tmp/pwned: {exc}",
            )
        )

    # ---- Check 2: process_running ----------------------------------
    # List all processes and look for anything non-standard that
    # might have been spawned by the exploit.
    try:
        stdout, stderr, exit_code = await agent.run(conn, "ps aux")
        if exit_code != 0:
            results.append(
                SSHCheck(
                    check_name="process_running",
                    passed=False,
                    details=f"Failed to list processes: {stderr}",
                )
            )
        else:
            # Define a set of well-known / expected processes that would
            # normally be running on a vanilla system.
            expected_processes: set[str] = {
                "root",
                "systemd",
                "sshd",
                "bash",
                "sh",
                "ps",
                "init",
                "kthreadd",
                "ksoftirqd",
                "migration",
                "watchdog",
                "events",
                "kworker",
                "kdevtmpfs",
                "netns",
                "rcu",
                "kernfs",
                "cgroup",
                "oom",
                "kmpathd",
                "jfsCommit",
                "xfs",
                "jbd2",
                "ext4",
                "flush",
                "kjournald",
                "syslogd",
                "klogd",
                "dbus-daemon",
                "inetd",
                "udevd",
                "dhclient",
                "NetworkManager",
                "rsyslogd",
                "cron",
                "atd",
                "acpid",
                "agetty",
                "login",
                "sshd",
            }

            lines = stdout.strip().split("\n")
            suspicious_lines: list[str] = []
            for line in lines:
                line_lower = line.lower()
                # Skip the header line
                if "user" in line_lower and "pid" in line_lower:
                    continue
                # Skip lines whose last column (COMMAND) contains only
                # expected entries.
                parts = line.strip().split()
                if len(parts) < 11:
                    continue
                command = parts[10] if len(parts) > 10 else parts[-1]
                cmd_name = command.split("/")[-1].split()[0].lower()
                if cmd_name not in expected_processes and cmd_name not in (
                    "ps",
                    "bash",
                    "sh",
                ):
                    # Whitelist common system utilities
                    if not any(
                        ign in cmd_name
                        for ign in [
                            "kworker",
                            "kthread",
                            "rcu",
                            "netns",
                        ]
                    ):
                        suspicious_lines.append(
                            f"Unexpected process: {line.strip()}"
                        )

            if suspicious_lines:
                results.append(
                    SSHCheck(
                        check_name="process_running",
                        passed=True,
                        details="Suspicious processes detected:\n"
                        + "\n".join(suspicious_lines[:5]),
                    )
                )
            else:
                results.append(
                    SSHCheck(
                        check_name="process_running",
                        passed=False,
                        details="No suspicious processes detected.",
                    )
                )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="process_running",
                passed=False,
                details=f"Error listing processes: {exc}",
            )
        )

    # ---- Check 3: network_listening ---------------------------------
    # Check for listening TCP ports to detect reverse shells or bind
    # shells opened by the exploit.
    try:
        stdout, stderr, exit_code = await agent.run(conn, "ss -tlnp")
        if exit_code != 0:
            results.append(
                SSHCheck(
                    check_name="network_listening",
                    passed=False,
                    details=f"Failed to list listening sockets: {stderr}",
                )
            )
        else:
            lines = stdout.strip().split("\n")
            listening_entries = [l for l in lines if "LISTEN" in l]
            # Filter out the SSH daemon itself (port 22) which is expected
            unexpected_listeners = [
                entry
                for entry in listening_entries
                if ":22" not in entry and "0.0.0.0:22" not in entry
            ]

            unexpected_listeners = [
                entry
                for entry in unexpected_listeners
                if not any(
                    skip in entry
                    for skip in ["127.0.0.1", "::1:"]
                )
            ]

            if unexpected_listeners:
                results.append(
                    SSHCheck(
                        check_name="network_listening",
                        passed=True,
                        details="Unexpected listening ports:\n"
                        + "\n".join(unexpected_listeners[:5]),
                    )
                )
            else:
                results.append(
                    SSHCheck(
                        check_name="network_listening",
                        passed=False,
                        details="No unexpected listening ports detected.",
                    )
                )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="network_listening",
                passed=False,
                details=f"Error checking network listeners: {exc}",
            )
        )

    # ---- Check 4: new_files_recent ----------------------------------
    # Find files created or modified in /tmp within the last 5 minutes,
    # which could indicate exploit payload delivery.
    try:
        stdout, stderr, exit_code = await agent.run(
            conn, "find /tmp -type f -mmin -5 2>/dev/null"
        )
        if exit_code != 0:
            results.append(
                SSHCheck(
                    check_name="new_files_recent",
                    passed=False,
                    details=f"Failed to list recent files: {stderr}",
                )
            )
        else:
            recent_files = [
                f.strip()
                for f in stdout.strip().split("\n")
                if f.strip()
            ]
            if recent_files:
                results.append(
                    SSHCheck(
                        check_name="new_files_recent",
                        passed=True,
                        details="Recently created files in /tmp:\n"
                        + "\n".join(recent_files[:10]),
                    )
                )
            else:
                results.append(
                    SSHCheck(
                        check_name="new_files_recent",
                        passed=False,
                        details="No recently created files found in /tmp.",
                    )
                )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="new_files_recent",
                passed=False,
                details=f"Error finding recent files: {exc}",
            )
        )

    return results
