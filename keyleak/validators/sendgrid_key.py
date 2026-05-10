"""SendGrid key validator — calls GET /v3/user/profile.

SendGrid API keys start with 'SG.' followed by two base64-like segments.
The /v3/user/profile endpoint returns the account owner's info.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

SENDGRID_API_BASE = "https://api.sendgrid.com/v3"
PROFILE_ENDPOINT = f"{SENDGRID_API_BASE}/user/profile"
REQUEST_TIMEOUT = 15.0


def validate(key: str) -> ValidationResult:
    """Validate a SendGrid API key by calling /v3/user/profile.

    Args:
        key: The SendGrid API key (SG.xxx.xxx).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith("SG."):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="sendgrid",
            status=KeyStatus.INVALID,
            message="Invalid format: SendGrid keys start with 'SG.'",
            response_time_ms=round(elapsed, 2),
        )

    # Validate structure: SG.part1.part2
    parts = key.split(".")
    if len(parts) != 3:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="sendgrid",
            status=KeyStatus.INVALID,
            message="Invalid format: SendGrid keys have format 'SG.xxx.xxx'",
            response_time_ms=round(elapsed, 2),
        )

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(PROFILE_ENDPOINT, headers=headers)

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            first_name = data.get("first_name", "")
            last_name = data.get("last_name", "")
            email = data.get("email", "unknown")
            company = data.get("company", "N/A")

            return ValidationResult(
                key_value=key,
                service="sendgrid",
                status=KeyStatus.VALID,
                message=f"Key is valid. Account: {first_name} {last_name}",
                account_info=f"Email: {email}, Company: {company}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code in (401, 403):
            return ValidationResult(
                key_value=key,
                service="sendgrid",
                status=KeyStatus.INVALID,
                message="Unauthorized — key is invalid or revoked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 429:
            return ValidationResult(
                key_value=key,
                service="sendgrid",
                status=KeyStatus.RATE_LIMITED,
                message="Rate limited by SendGrid.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="sendgrid",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="sendgrid",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="sendgrid",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
