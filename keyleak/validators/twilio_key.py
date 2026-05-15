"""Twilio key validator — calls GET /2010-04-01/Accounts.

Twilio API keys start with 'SK' followed by 32 hex characters.
Requires both API Key SID and Secret for authentication.
If only the SID is available, we validate format only.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

TWILIO_API_BASE = "https://api.twilio.com"
ACCOUNTS_ENDPOINT = f"{TWILIO_API_BASE}/2010-04-01/Accounts.json"
REQUEST_TIMEOUT = 15.0


def validate(key: str, secret: str | None = None) -> ValidationResult:
    """Validate a Twilio API key.

    Full validation requires both the API Key SID (SK...) and Secret.
    If only the SID is provided, format validation is performed.

    Args:
        key: The Twilio API Key SID (SK + 32 hex chars).
        secret: Optional API Key Secret for full validation.

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith("SK") or len(key) != 34:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="twilio",
            status=KeyStatus.INVALID,
            message="Invalid format: Twilio API keys are 'SK' + 32 hex chars",
            response_time_ms=round(elapsed, 2),
        )

    # Validate hex portion
    hex_part = key[2:]
    try:
        int(hex_part, 16)
    except ValueError:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="twilio",
            status=KeyStatus.INVALID,
            message="Invalid format: characters after 'SK' must be hexadecimal",
            response_time_ms=round(elapsed, 2),
        )

    if secret is None:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="twilio",
            status=KeyStatus.UNKNOWN,
            message="Format valid. Secret required for full verification.",
            response_time_ms=round(elapsed, 2),
        )

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(
                ACCOUNTS_ENDPOINT,
                auth=(key, secret),
            )

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            accounts = data.get("accounts", [])
            account_count = len(accounts)
            friendly_name = accounts[0].get("friendly_name", "N/A") if accounts else "N/A"

            return ValidationResult(
                key_value=key,
                service="twilio",
                status=KeyStatus.VALID,
                message=f"Key is valid. {account_count} account(s) accessible.",
                account_info=f"Primary account: {friendly_name}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            return ValidationResult(
                key_value=key,
                service="twilio",
                status=KeyStatus.INVALID,
                message="Unauthorized — key/secret combination is invalid.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 429:
            return ValidationResult(
                key_value=key,
                service="twilio",
                status=KeyStatus.RATE_LIMITED,
                message="Rate limited by Twilio.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="twilio",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="twilio",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="twilio",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
