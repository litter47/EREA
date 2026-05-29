"""Authentication Bypass verifier.

Checks for signs of authentication bypass by probing target HTTP
endpoints (provided in evidence) and looking for successful access
to previously-protected resources, admin panel indicators, and
session cookies.
"""

from __future__ import annotations

from typing import Optional

import httpx

from eva_agent.ssh.agent import SSHVerificationAgent
from eva_agent.task.models import SSHCheck


async def verify(
    agent: SSHVerificationAgent,
    conn: object,
    evidence: Optional[dict] = None,
) -> list[SSHCheck]:
    """Run authentication-bypass verification checks via HTTP.

    Args:
        agent: An SSHVerificationAgent instance.
        conn: An active SSHClientConnection (unused for HTTP checks).
        evidence: Optional dict that **must** contain at least
            ``"target_ip"`` and ``"target_port"`` keys to construct
            the target URL.  May optionally contain ``"target_path"``
            (default ``"/"``), ``"expected_status"`` (default ``200``),
            and ``"previous_status"`` (e.g. ``401`` or ``403``).

    Returns:
        A list of SSHCheck results.

    Raises:
        ValueError: If evidence is missing required keys.
        httpx.HTTPError: For HTTP-level failures.
    """
    evidence = evidence or {}

    target_ip: str | None = evidence.get("target_ip")
    target_port: int | str | None = evidence.get("target_port")
    target_path: str = evidence.get("target_path", "/")
    expected_status: int = int(evidence.get("expected_status", 200))
    previous_status: int = int(evidence.get("previous_status", 401))

    if not target_ip or not target_port:
        raise ValueError(
            "Auth bypass verifier requires 'target_ip' and 'target_port' in evidence."
        )

    base_url = f"http://{target_ip}:{target_port}"
    target_url = f"{base_url}{target_path}"

    results: list[SSHCheck] = []

    # ---- Check 1: access_protected ----------------------------------
    # Attempt to access the target URL.  A 200 response where a
    # non-200 (e.g. 401/403) was previously expected indicates a
    # possible authentication bypass.
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.get(target_url)

        status_code = response.status_code

        if status_code == expected_status and expected_status == 200:
            results.append(
                SSHCheck(
                    check_name="access_protected",
                    passed=True,
                    details=f"Target returned HTTP {status_code} (expected {expected_status}). "
                    f"Previously expected {previous_status}. "
                    f"URL: {target_url}",
                )
            )
        elif status_code != expected_status:
            results.append(
                SSHCheck(
                    check_name="access_protected",
                    passed=False,
                    details=f"Target returned HTTP {status_code} (expected {expected_status}). "
                    f"URL: {target_url}",
                )
            )
        else:
            results.append(
                SSHCheck(
                    check_name="access_protected",
                    passed=bool(expected_status == 200),
                    details=f"Target returned HTTP {status_code}. "
                    f"URL: {target_url}",
                )
            )

        # ---- Check 2: content_indicators ----------------------------
        # Inspect the response body for indicators of administrative
        # or authenticated content.
        content_lower = response.text.lower()

        admin_indicators = [
            "admin",
            "dashboard",
            "user list",
            "users",
            "administrator",
            "admin panel",
            "control panel",
            "management",
            "configuration",
            "settings",
            "logout",
            "welcome",
            "profile",
            "account",
            "user management",
            "role management",
            "system log",
            "audit log",
        ]

        found_indicators = [
            ind for ind in admin_indicators if ind in content_lower
        ]

        if found_indicators:
            results.append(
                SSHCheck(
                    check_name="content_indicators",
                    passed=True,
                    details=f"Found admin/authenticated content indicators in response: "
                    f"{', '.join(found_indicators[:8])}",
                )
            )
        else:
            results.append(
                SSHCheck(
                    check_name="content_indicators",
                    passed=False,
                    details="No admin panel or authenticated content indicators found "
                    "in the response body.",
                )
            )

        # ---- Check 3: session_check ---------------------------------
        # Look for Set-Cookie headers indicating that a session was
        # established (which should not happen for an unauthenticated
        # request to a protected resource).
        set_cookie_headers = response.headers.get_list("set-cookie")
        if not set_cookie_headers:
            # httpx normalises header names, also check lowercase
            set_cookie_headers = response.headers.get_list("Set-Cookie")

        if not set_cookie_headers:
            # Try raw headers iteration
            set_cookie_headers = [
                v for k, v in response.headers.items()
                if k.lower() == "set-cookie"
            ]

        session_indicators = [
            "session",
            "token",
            "auth",
            "sid",
            "jwt",
            "connect.sid",
            "csrf",
        ]

        if set_cookie_headers:
            found_session = False
            cookie_details: list[str] = []
            for cookie in set_cookie_headers:
                cookie_lower = cookie.lower()
                matched = [si for si in session_indicators if si in cookie_lower]
                if matched:
                    found_session = True
                    cookie_details.append(f"{cookie[:80]}")

            if found_session:
                results.append(
                    SSHCheck(
                        check_name="session_check",
                        passed=True,
                        details=f"Session/authentication cookies were set:\n"
                        + "\n".join(cookie_details[:5]),
                    )
                )
            else:
                results.append(
                    SSHCheck(
                        check_name="session_check",
                        passed=False,
                        details=f"Set-Cookie headers present but no session indicators found: "
                        f"{', '.join(set_cookie_headers[:3])}",
                    )
                )
        else:
            results.append(
                SSHCheck(
                    check_name="session_check",
                    passed=False,
                    details="No Set-Cookie headers in the response.",
                )
            )

    except httpx.TimeoutException:
        results.extend(
            [
                SSHCheck(
                    check_name="access_protected",
                    passed=False,
                    details=f"Request to {target_url} timed out.",
                ),
                SSHCheck(
                    check_name="content_indicators",
                    passed=False,
                    details="Skipped due to timeout.",
                ),
                SSHCheck(
                    check_name="session_check",
                    passed=False,
                    details="Skipped due to timeout.",
                ),
            ]
        )
    except (httpx.HTTPError, httpx.HTTPStatusError) as exc:
        results.extend(
            [
                SSHCheck(
                    check_name="access_protected",
                    passed=False,
                    details=f"HTTP error accessing {target_url}: {exc}",
                ),
                SSHCheck(
                    check_name="content_indicators",
                    passed=False,
                    details="Skipped due to HTTP error.",
                ),
                SSHCheck(
                    check_name="session_check",
                    passed=False,
                    details="Skipped due to HTTP error.",
                ),
            ]
        )
    except Exception as exc:
        results.extend(
            [
                SSHCheck(
                    check_name="access_protected",
                    passed=False,
                    details=f"Unexpected error: {exc}",
                ),
                SSHCheck(
                    check_name="content_indicators",
                    passed=False,
                    details="Skipped due to unexpected error.",
                ),
                SSHCheck(
                    check_name="session_check",
                    passed=False,
                    details="Skipped due to unexpected error.",
                ),
            ]
        )

    return results
