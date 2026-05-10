"""Anthropic key validator — calls POST /v1/messages with a tiny prompt.

Anthropic API keys start with 'sk-ant-'. We send a minimal request
to verify the key is valid without consuming significant credits.
"""

from __future__ import annotations

import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
MESSAGES_ENDPOINT = f"{ANTHROPIC_API_BASE}/messages"
REQUEST_TIMEOUT = 20.0


def validate(key: str) -> ValidationResult:
    """Validate an Anthropic API key by calling /v1/messages.

    Sends a minimal message to verify the key. Uses max_tokens=1
    to minimize cost.

    Args:
        key: The Anthropic API key (sk-ant-...).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not key.startswith("sk-ant-"):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="anthropic",
            status=KeyStatus.INVALID,
            message="Invalid format: Anthropic keys start with 'sk-ant-'",
            response_time_ms=round(elapsed, 2),
        )

    headers = {
        "x-api-key": key,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }

    payload = {
        "model": "claude-3-haiku-20240307",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}],
    }

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.post(
                MESSAGES_ENDPOINT, headers=headers, json=payload
            )

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code

        if status_code == 200:
            data = response.json()
            model = data.get("model", "unknown")
            usage = data.get("usage", {})
            input_tokens = usage.get("input_tokens", 0)

            return ValidationResult(
                key_value=key,
                service="anthropic",
                status=KeyStatus.VALID,
                message=f"Key is valid. Model: {model}",
                account_info=f"Input tokens used: {input_tokens}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 401:
            error_msg = response.json().get("error", {}).get("message", "Unauthorized")
            return ValidationResult(
                key_value=key,
                service="anthropic",
                status=KeyStatus.INVALID,
                message=f"Unauthorized — {error_msg}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 429:
            return ValidationResult(
                key_value=key,
                service="anthropic",
                status=KeyStatus.RATE_LIMITED,
                message="Rate limited — key may be valid but quota exceeded.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        elif status_code == 403:
            return ValidationResult(
                key_value=key,
                service="anthropic",
                status=KeyStatus.INVALID,
                message="Forbidden — key lacks permissions or is disabled.",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            body = response.text[:200]
            return ValidationResult(
                key_value=key,
                service="anthropic",
                status=KeyStatus.UNKNOWN,
                message=f"Unexpected HTTP {status_code}: {body}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="anthropic",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="anthropic",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
