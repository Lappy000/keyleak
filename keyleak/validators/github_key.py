"""GitHub key validator — calls GET /user to check token validity.

Supports personal access tokens (ghp_), OAuth tokens (gho_),
and fine-grained tokens (github_pat_).
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

GITHUB_API_BASE = "https://api.github.com"
USER_ENDPOINT = f"{GITHUB_API_BASE}/user"
REQUEST_TIMEOUT = 15.0


def _parse_scopes(headers: dict) -> str:
    """Extract OAuth scopes from response headers."""
    scopes = headers.get("x-oauth-scopes", "")
    if scopes:
        return scopes.strip()
    return "none (fine-grained token or no scopes)"


def _parse_rate_limit(headers: dict) -> str:
    """Extract rate limit info from response headers."""
    remaining = headers.get("x-ratelimit-remaining", "?")
    limit = headers.get("x-ratelimit-limit", "?")
    return f"{remaining}/{limit}"


def validate(key: str) -> ValidationResult:
    """Validate a GitHub token by calling /user.

    This endpoint returns the authenticated user's profile.
    It is a safe, read-only call.

    Args:
        key: The GitHub token (ghp_/gho_/github_pat_...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    valid_prefixes = ("ghp_", "gho_", "github_pat_")
    if not any(key.startswith(p) for p in valid_prefixes):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="github",
            status=KeyStatus.INVALID,
            message=f"Invalid format: GitHub tokens start with {valid_prefixes}",
            response_time_ms=round(elapsed, 2),
        )

    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(USER_ENDPOINT, headers=headers)

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code
        resp_headers = dict(response.headers)

        if status_code == 200:
            data = response.json()
            username = data.get("login", "unknown")
            name = data.get("name", "N/A")
            email = data.get("email", "N/A")
            scopes = _parse_scopes(resp_headers)
            rate_info = _parse_rate_limit(resp_headers)

            return ValidationResult(
                key_value=key,
                service="github",
                status=KeyStatus.VALID,
                message=f"Key is valid. User: {username} ({name})",
                account_info=f"Email: {email}, Rate limit: {rate_info}",
                permissions=f"Scopes: {scopes}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            return ValidationResult(
                key_value=key,
                service="github",
                status=KeyStatus.INVALID,
                message="Unauthorized — token is invalid or revoked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 403:
            return ValidationResult(
                key_value=key,
                service="github",
                status=KeyStatus.RATE_LIMITED,
                message="Forbidden — token may be valid but rate limited or IP blocked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="github",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="github",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="github",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
