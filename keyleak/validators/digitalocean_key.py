"""DigitalOcean key validator — calls GET /v2/account.

DigitalOcean personal access tokens start with 'dop_v1_' followed
by 64 hexadecimal characters. The /v2/account endpoint returns
account information.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

DO_API_BASE = "https://api.digitalocean.com/v2"
ACCOUNT_ENDPOINT = f"{DO_API_BASE}/account"
REQUEST_TIMEOUT = 15.0


def validate(key: str) -> ValidationResult:
    """Validate a DigitalOcean token by calling /v2/account.

    Args:
        key: The DigitalOcean token (dop_v1_...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith("dop_v1_"):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="digitalocean",
            status=KeyStatus.INVALID,
            message="Invalid format: DO tokens start with 'dop_v1_'",
            response_time_ms=round(elapsed, 2),
        )

    if len(key) != 71:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="digitalocean",
            status=KeyStatus.INVALID,
            message=f"Invalid format: DO tokens are 71 chars (got {len(key)})",
            response_time_ms=round(elapsed, 2),
        )

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(ACCOUNT_ENDPOINT, headers=headers)

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            account = data.get("account", {})
            email = account.get("email", "unknown")
            droplet_limit = account.get("droplet_limit", 0)
            status_text = account.get("status", "unknown")
            team_name = account.get("team", {}).get("name", "personal")
            uuid = account.get("uuid", "N/A")

            return ValidationResult(
                key_value=key,
                service="digitalocean",
                status=KeyStatus.VALID,
                message=f"Key is valid. Account: {email} (status: {status_text})",
                account_info=f"UUID: {uuid}, Team: {team_name}, Droplet limit: {droplet_limit}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            return ValidationResult(
                key_value=key,
                service="digitalocean",
                status=KeyStatus.INVALID,
                message="Unauthorized — token is invalid or revoked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 429:
            return ValidationResult(
                key_value=key,
                service="digitalocean",
                status=KeyStatus.RATE_LIMITED,
                message="Rate limited by DigitalOcean.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="digitalocean",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="digitalocean",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="digitalocean",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
