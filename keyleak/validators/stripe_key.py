"""Stripe key validator — calls GET /v1/charges?limit=1 to check validity.

Stripe secret keys start with sk_live_ (production) or sk_test_ (test mode).
Calling /v1/charges with limit=1 is a safe read-only operation.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

STRIPE_API_BASE = "https://api.stripe.com/v1"
CHARGES_ENDPOINT = f"{STRIPE_API_BASE}/charges"
REQUEST_TIMEOUT = 15.0


def _detect_mode(key: str) -> str:
    """Determine if the key is live or test mode."""
    if key.startswith("sk_live_"):
        return "live"
    elif key.startswith("sk_test_"):
        return "test"
    return "unknown"


def validate(key: str) -> ValidationResult:
    """Validate a Stripe secret key by calling /v1/charges?limit=1.

    Args:
        key: The Stripe secret key (sk_live_/sk_test_...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith(("sk_live_", "sk_test_")):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="stripe",
            status=KeyStatus.INVALID,
            message="Invalid format: Stripe keys start with 'sk_live_' or 'sk_test_'",
            response_time_ms=round(elapsed, 2),
        )

    mode = _detect_mode(key)

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(
                CHARGES_ENDPOINT,
                params={"limit": 1},
                auth=(key, ""),
            )

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            charge_count = len(data.get("data", []))
            has_more = data.get("has_more", False)

            return ValidationResult(
                key_value=key,
                service="stripe",
                status=KeyStatus.VALID,
                message=f"Key is valid ({mode} mode). Retrieved {charge_count} charge(s).",
                account_info=f"Mode: {mode}, Has more charges: {has_more}",
                permissions="charges:read",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            return ValidationResult(
                key_value=key,
                service="stripe",
                status=KeyStatus.INVALID,
                message="Unauthorized — key is invalid or revoked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 429:
            return ValidationResult(
                key_value=key,
                service="stripe",
                status=KeyStatus.RATE_LIMITED,
                message="Rate limited — key may be valid.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="stripe",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="stripe",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="stripe",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
