"""Telegram Bot key validator — calls getMe to verify bot token.

Telegram bot tokens have the format: <bot_id>:<alphanumeric_hash>
where bot_id is 8-10 digits and hash is 35 alphanumeric characters.
"""

from __future__ import annotations

import re
import time

import httpx

from keyleak.validators import KeyStatus, ValidationResult

TELEGRAM_API_BASE = "https://api.telegram.org"
REQUEST_TIMEOUT = 15.0

TOKEN_PATTERN = re.compile(r"^\d{8,10}:[A-Za-z0-9_-]{35}$")


def validate(key: str) -> ValidationResult:
    """Validate a Telegram bot token by calling getMe.

    The getMe method returns basic information about the bot.
    It's a safe, read-only operation.

    Args:
        key: The Telegram bot token (digits:alphanum).

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    if not TOKEN_PATTERN.match(key):
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="telegram",
            status=KeyStatus.INVALID,
            message="Invalid format: Telegram tokens are '<bot_id>:<35_char_hash>'",
            response_time_ms=round(elapsed, 2),
        )

    url = f"{TELEGRAM_API_BASE}/bot{key}/getMe"

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(url)

        elapsed = (time.time() - start_time) * 1000
        status_code = response.status_code
        data = response.json()

        if data.get("ok"):
            result = data.get("result", {})
            bot_name = result.get("first_name", "Unknown")
            username = result.get("username", "unknown")
            bot_id = result.get("id", "unknown")
            can_join_groups = result.get("can_join_groups", False)
            can_read_messages = result.get("can_read_all_group_messages", False)

            return ValidationResult(
                key_value=key,
                service="telegram",
                status=KeyStatus.VALID,
                message=f"Bot token is valid. Bot: {bot_name} (@{username})",
                account_info=f"Bot ID: {bot_id}",
                permissions=f"Join groups: {can_join_groups}, Read all: {can_read_messages}",
                http_status=status_code,
                response_time_ms=round(elapsed, 2),
            )
        else:
            error_code = data.get("error_code", 0)
            description = data.get("description", "Unknown error")

            if error_code == 401:
                return ValidationResult(
                    key_value=key,
                    service="telegram",
                    status=KeyStatus.INVALID,
                    message=f"Unauthorized — {description}",
                    http_status=401,
                    response_time_ms=round(elapsed, 2),
                )
            else:
                return ValidationResult(
                    key_value=key,
                    service="telegram",
                    status=KeyStatus.UNKNOWN,
                    message=f"Telegram error {error_code}: {description}",
                    http_status=error_code,
                    response_time_ms=round(elapsed, 2),
                )

    except httpx.TimeoutException:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="telegram",
            status=KeyStatus.ERROR,
            message=f"Request timed out after {REQUEST_TIMEOUT}s",
            response_time_ms=round(elapsed, 2),
        )
    except httpx.HTTPError as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="telegram",
            status=KeyStatus.ERROR,
            message=f"HTTP error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
