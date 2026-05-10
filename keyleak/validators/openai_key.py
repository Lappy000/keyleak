"""OpenAI key validator — calls GET /v1/models to check validity.

A valid OpenAI key will return a list of available models.
An invalid key returns 401 Unauthorized.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

OPENAI_API_BASE = "https://api.openai.com/v1"
MODELS_ENDPOINT = f"{OPENAI_API_BASE}/models"
REQUEST_TIMEOUT = 15.0


def validate(key: str) -> ValidationResult:
    """Validate an OpenAI API key by calling /v1/models.

    This is a read-only endpoint that lists available models.
    It does not consume any tokens or credits.

    Args:
        key: The OpenAI API key (sk-...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith("sk-"):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="openai",
            status=KeyStatus.INVALID,
            message="Invalid format: OpenAI keys start with 'sk-'",
            response_time_ms=round(elapsed, 2),
        )

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(MODELS_ENDPOINT, headers=headers)

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            model_count = len(data.get("data", []))
            model_names = [m.get("id", "?") for m in data.get("data", [])[:5]]
            models_preview = ", ".join(model_names)
            return ValidationResult(
                key_value=key,
                service="openai",
                status=KeyStatus.VALID,
                message=f"Key is valid. {model_count} models available.",
                account_info=f"Sample models: {models_preview}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            return ValidationResult(
                key_value=key,
                service="openai",
                status=KeyStatus.INVALID,
                message="Unauthorized — key is invalid or revoked.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 429:
            return ValidationResult(
                key_value=key,
                service="openai",
                status=KeyStatus.RATE_LIMITED,
                message="Rate limited — key may be valid but quota exceeded.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="openai",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="openai",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="openai",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
