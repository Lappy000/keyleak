"""Validators package — each module validates keys for a specific service."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class KeyStatus(Enum):
    """Result status for a key validation check."""
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class ValidationResult:
    """Holds the outcome of validating an API key."""

    key_value: str
    service: str
    status: KeyStatus
    message: str = ""
    account_info: Optional[str] = None
    permissions: Optional[str] = None
    http_status: Optional[int] = None
    response_time_ms: Optional[float] = None

    @property
    def is_active(self) -> bool:
        """Check if the key is currently active/valid."""
        return self.status == KeyStatus.VALID

    @property
    def status_emoji(self) -> str:
        """Return an emoji for the status."""
        emoji_map = {
            KeyStatus.VALID: "✅",
            KeyStatus.INVALID: "❌",
            KeyStatus.EXPIRED: "⏰",
            KeyStatus.RATE_LIMITED: "🚦",
            KeyStatus.ERROR: "⚠️",
            KeyStatus.UNKNOWN: "❓",
        }
        return emoji_map.get(self.status, "❓")

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        return {
            "key": self.key_value[:8] + "..." if len(self.key_value) > 8 else self.key_value,
            "service": self.service,
            "status": self.status.value,
            "message": self.message,
            "account_info": self.account_info,
            "permissions": self.permissions,
            "http_status": self.http_status,
            "response_time_ms": self.response_time_ms,
        }


# Mapping from service name to validator module path
_VALIDATOR_MODULES = {
    "aws": "keyleak.validators.aws",
    "openai": "keyleak.validators.openai_key",
    "anthropic": "keyleak.validators.anthropic_key",
    "github": "keyleak.validators.github_key",
    "stripe": "keyleak.validators.stripe_key",
    "slack": "keyleak.validators.slack_key",
    "sendgrid": "keyleak.validators.sendgrid_key",
    "twilio": "keyleak.validators.twilio_key",
    "telegram": "keyleak.validators.telegram_key",
    "digitalocean": "keyleak.validators.digitalocean_key",
}


def get_validator(service: str):
    """Dynamically import and return the validator module for a service.

    Args:
        service: The service name (e.g. 'aws', 'github').

    Returns:
        The validator module, which must have a `validate(key: str) -> ValidationResult` function.

    Raises:
        ValueError: If the service is not supported.
        ImportError: If the module cannot be loaded.
    """
    module_path = _VALIDATOR_MODULES.get(service)
    if not module_path:
        raise ValueError(f"Unsupported service: {service}")
    return importlib.import_module(module_path)


def validate_key(service: str, key: str) -> ValidationResult:
    """Validate a key for the given service.

    Args:
        service: Service name.
        key: Raw API key string.

    Returns:
        ValidationResult with the outcome.
    """
    try:
        module = get_validator(service)
        return module.validate(key)
    except ValueError as exc:
        return ValidationResult(
            key_value=key,
            service=service,
            status=KeyStatus.ERROR,
            message=str(exc),
        )
    except Exception as exc:
        return ValidationResult(
            key_value=key,
            service=service,
            status=KeyStatus.ERROR,
            message=f"Unexpected error: {exc}",
        )
