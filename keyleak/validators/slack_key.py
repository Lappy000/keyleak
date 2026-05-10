"""Slack key validator — calls auth.test to check token validity.

Supports bot tokens (xoxb-) and user tokens (xoxp-).
The auth.test method is a safe endpoint that returns workspace info.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

SLACK_AUTH_TEST = "https://slack.com/api/auth.test"
REQUEST_TIMEOUT = 15.0


def validate(key: str) -> ValidationResult:
    """Validate a Slack token by calling auth.test.

    Args:
        key: The Slack token (xoxb-/xoxp-...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith(("xoxb-", "xoxp-")):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="slack",
            status=KeyStatus.INVALID,
            message="Invalid format: Slack tokens start with 'xoxb-' or 'xoxp-'",
            response_time_ms=round(elapsed, 2),
        )

    token_type = "bot" if key.startswith("xoxb-") else "user"
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.post(SLACK_AUTH_TEST, headers=headers)

        elapsed = (time.time() - start_time) * 1000
        data = response.json()

        if data.get("ok"):
            team = data.get("team", "unknown")
            user = data.get("user", "unknown")
            team_id = data.get("team_id", "unknown")
            user_id = data.get("user_id", "unknown")

            return ValidationResult(
                key_value=key,
                service="slack",
                status=KeyStatus.VALID,
                message=f"Key is valid ({token_type} token). Team: {team}",
                account_info=f"User: {user} ({user_id}), Team ID: {team_id}",
                http_status=200,
                response_time_ms=round(elapsed, 2),
            )
        else:
            error = data.get("error", "unknown_error")
            if error in ("invalid_auth", "token_revoked", "token_expired"):
                status = KeyStatus.INVALID if error != "token_expired" else KeyStatus.EXPIRED
                return ValidationResult(
                    key_value=key,
                    service="slack",
                    status=status,
                    message=f"Token rejected: {error}",
                    http_status=response.status_code,
                    response_time_ms=round(elapsed, 2),
                )
            elif error == "ratelimited":
                return ValidationResult(
                    key_value=key,
                    service="slack",
                    status=KeyStatus.RATE_LIMITED,
                    message="Rate limited by Slack.",
                    http_status=429,
                    response_time_ms=round(elapsed, 2),
                )
            else:
                return ValidationResult(
                    key_value=key,
                    service="slack",
                    status=KeyStatus.UNKNOWN,
                    message=f"Slack API error: {error}",
                    http_status=response.status_code,
                    response_time_ms=round(elapsed, 2),
                )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="slack",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="slack",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
