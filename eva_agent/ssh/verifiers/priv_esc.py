"""Privilege Escalation verifier.

Checks for signs of privilege escalation on the remote host by
examining the current user context, sudo access rights, changes
in UID (compared to a baseline), and visible root-level processes.
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
    """Run privilege-escalation verification checks.

    Args:
        agent: An SSHVerificationAgent instance.
        conn: An active SSHClientConnection.
        evidence: Optional dict.  If it contains a ``"baseline_uid"``
            key, the current UID will be compared against it to detect
            elevation.

    Returns:
        A list of SSHCheck results.
    """
    evidence = evidence or {}
    results: list[SSHCheck] = []

    # ---- Check 1: current_user ---------------------------------------
    # Run 'whoami' and 'id' to determine the current user context.
    try:
        whoami_stdout, whoami_stderr, whoami_ec = await agent.run(conn, "whoami")
        id_stdout, id_stderr, id_ec = await agent.run(conn, "id")

        is_root: bool = False
        current_uid: str = "unknown"
        current_user: str = whoami_stdout.strip() if whoami_stdout else "unknown"

        if id_stdout:
            current_uid = id_stdout.strip()
            if "uid=0" in current_uid:
                is_root = True

        if is_root:
            results.append(
                SSHCheck(
                    check_name="current_user",
                    passed=True,
                    details=f"Current user is root. whoami: {current_user}, id: {current_uid}",
                )
            )
        else:
            results.append(
                SSHCheck(
                    check_name="current_user",
                    passed=False,
                    details=f"Current user is not root. whoami: {current_user}, id: {current_uid}",
                )
            )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="current_user",
                passed=False,
                details=f"Error determining current user: {exc}",
            )
        )

    # ---- Check 2: sudo_access ---------------------------------------
    # Check whether sudo is available and whether the current user can
    # run commands as root without a password.
    try:
        sudo_stdout, sudo_stderr, sudo_ec = await agent.run(
            conn,
            "sudo -n true 2>/dev/null && echo 'sudo_available'",
        )
        if "sudo_available" in sudo_stdout:
            results.append(
                SSHCheck(
                    check_name="sudo_access",
                    passed=True,
                    details="User has passwordless sudo access (sudo -n true succeeded).",
                )
            )
        else:
            # Try sudo -l for more detail
            sudo_l_stdout, sudo_l_stderr, sudo_l_ec = await agent.run(
                conn,
                "sudo -l 2>/dev/null",
            )
            if sudo_l_ec == 0 and sudo_l_stdout and "not allowed" not in sudo_l_stdout.lower():
                results.append(
                    SSHCheck(
                        check_name="sudo_access",
                        passed=True,
                        details=f"User has sudo privileges:\n{sudo_l_stdout.strip()}",
                    )
                )
            else:
                results.append(
                    SSHCheck(
                        check_name="sudo_access",
                        passed=False,
                        details="User does not have visible sudo access.",
                    )
                )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="sudo_access",
                passed=False,
                details=f"Error checking sudo access: {exc}",
            )
        )

    # ---- Check 3: uid_changed ---------------------------------------
    # Compare the current UID against a baseline supplied in evidence.
    # If the baseline differs, the user's identity has changed (possibly
    # escalated).
    baseline_uid: Optional[str] = evidence.get("baseline_uid")
    if baseline_uid is not None:
        try:
            id_stdout, id_stderr, id_ec = await agent.run(conn, "id -u")
            current_uid_num: str = id_stdout.strip() if id_stdout else ""

            if current_uid_num and current_uid_num != str(baseline_uid):
                results.append(
                    SSHCheck(
                        check_name="uid_changed",
                        passed=True,
                        details=f"UID changed from {baseline_uid} to {current_uid_num}. "
                        f"Possible privilege escalation detected.",
                    )
                )
            elif current_uid_num:
                results.append(
                    SSHCheck(
                        check_name="uid_changed",
                        passed=False,
                        details=f"UID unchanged (baseline={baseline_uid}, current={current_uid_num}).",
                    )
                )
            else:
                results.append(
                    SSHCheck(
                        check_name="uid_changed",
                        passed=False,
                        details=f"Could not determine current UID.",
                    )
                )
        except Exception as exc:
            results.append(
                SSHCheck(
                    check_name="uid_changed",
                    passed=False,
                    details=f"Error comparing UIDs: {exc}",
                )
            )
    else:
        results.append(
            SSHCheck(
                check_name="uid_changed",
                passed=False,
                details="No baseline UID provided in evidence; skipping comparison.",
            )
        )

    # ---- Check 4: root_processes ------------------------------------
    # List processes running as root to see what is visible from the
    # current user context.  A non-root user listing root processes
    # may indicate a privilege boundary issue.
    try:
        stdout, stderr, exit_code = await agent.run(conn, "ps -U root 2>/dev/null")
        if exit_code != 0 or not stdout:
            results.append(
                SSHCheck(
                    check_name="root_processes",
                    passed=False,
                    details=f"Could not list root processes: {stderr}",
                )
            )
        else:
            lines = stdout.strip().split("\n")
            # Count root processes (skipping header line)
            root_proc_count = max(0, len(lines) - 1)
            # Extract process names for summary
            proc_names = []
            for line in lines[1:]:  # skip header
                parts = line.strip().split()
                if len(parts) >= 11:
                    proc_names.append(parts[10])
                elif len(parts) >= 4:
                    proc_names.append(parts[-1])

            # Detect if any of these are unusual for the given context
            expected_root_procs = {
                "systemd",
                "sshd",
                "bash",
                "sh",
                "login",
                "init",
                "kthreadd",
                "ps",
                "python3",
                "python",
                "node",
                "java",
                "nginx",
                "apache2",
                "httpd",
                "mysqld",
                "postgres",
                "cron",
                "rsyslogd",
                "dbus-daemon",
                "agetty",
                "dhclient",
                "NetworkManager",
                "udevd",
            }
            unusual_procs = [
                p for p in proc_names if p.lower() not in expected_root_procs
            ]

            if unusual_procs and len(unusual_procs) <= len(proc_names) * 0.3:
                details = (
                    f"{root_proc_count} root process(es) visible. "
                    f"Unusual: {', '.join(unusual_procs[:5])}"
                )
            else:
                details = f"{root_proc_count} root process(es) visible."

            results.append(
                SSHCheck(
                    check_name="root_processes",
                    passed=True,
                    details=details,
                )
            )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="root_processes",
                passed=False,
                details=f"Error listing root processes: {exc}",
            )
        )

    return results
