"""Mailgun API key validator — calls GET /v3/domains to check key validity.

Supports Mailgun private API keys (key-xxx format) used for
sending email, managing domains, and accessing analytics.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

MAILGUN_API_BASE = "https://api.mailgun.net/v3"
DOMAINS_ENDPOINT = f"{MAILGUN_API_BASE}/domains"
REQUEST_TIMEOUT = 15.0


def validate(key: str) -> ValidationResult:
    """Validate a Mailgun API key by calling GET /v3/domains.

    This endpoint lists the sending domains. It's a safe, read-only call
    that confirms the key is active and reveals scope information.

    Args:
        key: The Mailgun API key (key-... or pubkey-...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    valid_prefixes = ("key-", "pubkey-")
    if not any(key.startswith(p) for p in valid_prefixes):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="mailgun",
            status=KeyStatus.INVALID,
            message=f"Invalid format: Mailgun keys start with {valid_prefixes}",
            response_time_ms=round(elapsed, 2),
        )

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(
                DOMAINS_ENDPOINT,
                auth=("api", key),
            )

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            total_count = data.get("total_count", 0)
            items = data.get("items", [])
            domain_names = [d.get("name", "?") for d in items[:3]]
            domain_info = ", ".join(domain_names) if domain_names else "no domains"

            return ValidationResult(
                key_value=key,
                service="mailgun",
                status=KeyStatus.VALID,
                message=f"Key is valid. {total_count} domain(s) accessible.",
                account_info=f"Domains: {domain_info}",
                permissions="private-key" if key.startswith("key-") else "public-key",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            return ValidationResult(
                key_value=key,
                service="mailgun",
                status=KeyStatus.INVALID,
                message="Unauthorized — key is invalid or revoked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 403:
            return ValidationResult(
                key_value=key,
                service="mailgun",
                status=KeyStatus.VALID,
                message="Key is valid but lacks domain listing permission.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="mailgun",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="mailgun",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="mailgun",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
