"""Information Leakage verifier.

Checks for signs of information disclosure on the remote host, such
as readable shadow files, password file analysis, and exposure of
sensitive configuration files.
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
    """Run information-leakage verification checks.

    Args:
        agent: An SSHVerificationAgent instance.
        conn: An active SSHClientConnection.
        evidence: Optional contextual evidence dict (unused for
            info_leak).

    Returns:
        A list of SSHCheck results.
    """
    results: list[SSHCheck] = []

    # ---- Check 1: shadow_readable -----------------------------------
    # Attempt to read /etc/shadow.  A non-empty result containing root
    # password hash data indicates that the current user can read this
    # normally-restricted file.
    try:
        stdout, stderr, exit_code = await agent.run(
            conn, "cat /etc/shadow 2>/dev/null"
        )
        if stdout and "root:" in stdout:
            # Extract the root hash line for evidence
            root_line = ""
            for line in stdout.split("\n"):
                if line.startswith("root:"):
                    root_line = line[:80]  # truncate for safety
                    break
            results.append(
                SSHCheck(
                    check_name="shadow_readable",
                    passed=True,
                    details=f"/etc/shadow is readable by current user. "
                    f"Root entry: {root_line}",
                )
            )
        elif exit_code != 0 and stderr:
            results.append(
                SSHCheck(
                    check_name="shadow_readable",
                    passed=False,
                    details=f"/etc/shadow is not readable (access denied).",
                )
            )
        else:
            results.append(
                SSHCheck(
                    check_name="shadow_readable",
                    passed=False,
                    details="/etc/shadow is not readable or contains no root entry.",
                )
            )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="shadow_readable",
                passed=False,
                details=f"Error reading /etc/shadow: {exc}",
            )
        )

    # ---- Check 2: passwd_contents -----------------------------------
    # Read /etc/passwd and count the number of users that have a valid
    # login shell, indicating potential accounts available on the system.
    try:
        stdout, stderr, exit_code = await agent.run(
            conn, "cat /etc/passwd 2>/dev/null"
        )
        if exit_code != 0 or not stdout:
            results.append(
                SSHCheck(
                    check_name="passwd_contents",
                    passed=False,
                    details=f"Failed to read /etc/passwd: {stderr}",
                )
            )
        else:
            lines = stdout.strip().split("\n")
            total_users = len(lines)
            shell_users = 0
            for line in lines:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    shell = parts[6]
                    if shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                        shell_users += 1

            # List notable users (human accounts or services)
            notable_users = []
            for line in lines:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    uid = int(parts[2])
                    # UID 0 = root, UID 1000+ = regular users
                    if uid == 0 or 1000 <= uid < 65534:
                        notable_users.append(parts[0])

            details_parts = [
                f"Total entries: {total_users}",
                f"Users with login shells: {shell_users}",
            ]
            if notable_users:
                details_parts.append(
                    f"Notable users: {', '.join(notable_users)}"
                )

            results.append(
                SSHCheck(
                    check_name="passwd_contents",
                    passed=True,
                    details="; ".join(details_parts),
                )
            )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="passwd_contents",
                passed=False,
                details=f"Error reading /etc/passwd: {exc}",
            )
        )

    # ---- Check 3: sensitive_configs ---------------------------------
    # Probe for common sensitive configuration files that should not be
    # world-readable.
    sensitive_paths = [
        "/var/www/html/.env",
        "/var/www/html/config/database.yml",
        "/var/www/html/wp-config.php",
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled/default",
        "/etc/apache2/apache2.conf",
        "/etc/mysql/my.cnf",
        "/etc/postgresql/postgresql.conf",
        "/root/.ssh/id_rsa",
        "/root/.ssh/authorized_keys",
        "/home/*/.ssh/id_rsa",
        "/home/*/.ssh/authorized_keys",
        "/etc/kubernetes/admin.conf",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/etc/ssl/private/ssl-cert-snakeoil.key",
        "/opt/bitnami/wordpress/wp-config.php",
        "/app/.env",
        "/etc/environment",
        "/proc/self/environ",
    ]

    try:
        found_configs = []
        for config_path in sensitive_paths:
            stdout, stderr, exit_code = await agent.run(
                conn,
                f"cat {config_path} 2>/dev/null | head -c 500",
            )
            if exit_code == 0 and stdout.strip():
                # Avoid counting "file not found" as positive
                if "no such file" not in stdout.lower():
                    found_configs.append(config_path)

        if found_configs:
            results.append(
                SSHCheck(
                    check_name="sensitive_configs",
                    passed=True,
                    details="Readable sensitive configuration files:\n"
                    + "\n".join(found_configs[:10]),
                )
            )
        else:
            results.append(
                SSHCheck(
                    check_name="sensitive_configs",
                    passed=False,
                    details="No readable sensitive configuration files found.",
                )
            )
    except Exception as exc:
        results.append(
            SSHCheck(
                check_name="sensitive_configs",
                passed=False,
                details=f"Error checking sensitive configs: {exc}",
            )
        )

    return results
