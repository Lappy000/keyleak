"""Hugging Face API token validator — calls GET /api/whoami-v2 to check validity.

Supports Hugging Face user access tokens (hf_xxx format) used for
accessing models, datasets, and inference APIs on the Hugging Face Hub.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

HF_API_BASE = "https://huggingface.co"
WHOAMI_ENDPOINT = f"{HF_API_BASE}/api/whoami-v2"
REQUEST_TIMEOUT = 15.0


def validate(key: str) -> ValidationResult:
    """Validate a Hugging Face token by calling GET /api/whoami-v2.

    This endpoint returns the authenticated user or organization info.
    It is a safe, read-only call.

    Args:
        key: The Hugging Face token (hf_...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith("hf_"):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="huggingface",
            status=KeyStatus.INVALID,
            message="Invalid format: Hugging Face tokens start with 'hf_'",
            response_time_ms=round(elapsed, 2),
        )

    headers = {
        "Authorization": f"Bearer {key}",
    }

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(WHOAMI_ENDPOINT, headers=headers)

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            username = data.get("name", "unknown")
            fullname = data.get("fullname", "N/A")
            email = data.get("email", "N/A")

            # Extract token permissions/scopes
            auth_info = data.get("auth", {})
            token_type = auth_info.get("type", "unknown")
            scopes = auth_info.get("accessToken", {}).get("role", "unknown")

            return ValidationResult(
                key_value=key,
                service="huggingface",
                status=KeyStatus.VALID,
                message=f"Token is valid. User: {username} ({fullname})",
                account_info=f"Email: {email}, Token type: {token_type}",
                permissions=f"Role: {scopes}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            return ValidationResult(
                key_value=key,
                service="huggingface",
                status=KeyStatus.INVALID,
                message="Unauthorized — token is invalid or revoked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 403:
            return ValidationResult(
                key_value=key,
                service="huggingface",
                status=KeyStatus.VALID,
                message="Token is valid but has restricted permissions.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 429:
            return ValidationResult(
                key_value=key,
                service="huggingface",
                status=KeyStatus.RATE_LIMITED,
                message="Rate limited — try again later.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="huggingface",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="huggingface",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="huggingface",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
