"""Tests for keyleak.validators — base classes and dynamic loading."""

import pytest

from keyleak.validators import (
    KeyStatus,
    ValidationResult,
    get_validator,
    validate_key,
)


class TestKeyStatus:
    """Test KeyStatus enum values."""

    def test_all_statuses_exist(self):
        assert KeyStatus.VALID.value == "valid"
        assert KeyStatus.INVALID.value == "invalid"
        assert KeyStatus.EXPIRED.value == "expired"
        assert KeyStatus.RATE_LIMITED.value == "rate_limited"
        assert KeyStatus.ERROR.value == "error"
        assert KeyStatus.UNKNOWN.value == "unknown"


class TestValidationResult:
    """Test ValidationResult dataclass."""

    def test_is_active_when_valid(self):
        result = ValidationResult(
            key_value="test_key",
            service="test",
            status=KeyStatus.VALID,
            message="Valid",
        )
        assert result.is_active is True

    def test_not_active_when_invalid(self):
        result = ValidationResult(
            key_value="test_key",
            service="test",
            status=KeyStatus.INVALID,
            message="Invalid",
        )
        assert result.is_active is False

    def test_status_emoji_valid(self):
        result = ValidationResult(
            key_value="k", service="s", status=KeyStatus.VALID
        )
        assert result.status_emoji == "✅"

    def test_status_emoji_invalid(self):
        result = ValidationResult(
            key_value="k", service="s", status=KeyStatus.INVALID
        )
        assert result.status_emoji == "❌"

    def test_to_dict_masks_long_key(self):
        result = ValidationResult(
            key_value="sk-1234567890abcdef",
            service="openai",
            status=KeyStatus.VALID,
            message="OK",
            http_status=200,
            response_time_ms=42.5,
        )
        d = result.to_dict()
        assert d["key"] == "sk-12345..."
        assert d["service"] == "openai"
        assert d["status"] == "valid"
        assert d["http_status"] == 200
        assert d["response_time_ms"] == 42.5

    def test_to_dict_short_key_not_masked(self):
        result = ValidationResult(
            key_value="short",
            service="test",
            status=KeyStatus.ERROR,
        )
        d = result.to_dict()
        assert d["key"] == "short"

    def test_optional_fields_default_none(self):
        result = ValidationResult(
            key_value="k", service="s", status=KeyStatus.UNKNOWN
        )
        assert result.account_info is None
        assert result.permissions is None
        assert result.http_status is None
        assert result.response_time_ms is None


class TestGetValidator:
    """Test dynamic validator loading."""

    @pytest.mark.parametrize(
        "service",
        [
            "aws",
            "openai",
            "anthropic",
            "github",
            "stripe",
            "slack",
            "sendgrid",
            "twilio",
            "telegram",
            "digitalocean",
            "mailgun",
            "huggingface",
        ],
    )
    def test_all_registered_validators_loadable(self, service):
        module = get_validator(service)
        assert hasattr(module, "validate")
        assert callable(module.validate)

    def test_unknown_service_raises_valueerror(self):
        with pytest.raises(ValueError, match="Unsupported service"):
            get_validator("nonexistent_service_xyz")


class TestValidateKey:
    """Test the validate_key wrapper function."""

    def test_unknown_service_returns_error_result(self):
        result = validate_key("fake_service", "fake_key")
        assert result.status == KeyStatus.ERROR
        assert "Unsupported service" in result.message

    def test_invalid_key_format_returns_invalid(self):
        # GitHub validator should reject a key that doesn't start with ghp_/gho_/github_pat_
        result = validate_key("github", "invalid_key_no_prefix")
        assert result.status == KeyStatus.INVALID
        assert result.service == "github"

    def test_mailgun_invalid_prefix(self):
        result = validate_key("mailgun", "invalid_not_key_prefix")
        assert result.status == KeyStatus.INVALID

    def test_huggingface_invalid_prefix(self):
        result = validate_key("huggingface", "not_hf_prefix")
        assert result.status == KeyStatus.INVALID
