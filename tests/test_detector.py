"""Tests for keyleak.detector — key pattern detection engine."""

import pytest

from keyleak.detector import (
    DetectedKey,
    KeyDetector,
    KeyPattern,
    get_all_patterns,
    get_supported_services,
)


class TestKeyDetectorInit:
    """Test KeyDetector initialization and configuration."""

    def test_default_loads_all_patterns(self):
        detector = KeyDetector()
        services = detector.supported_services
        assert len(services) >= 12
        assert "aws" in services
        assert "github" in services
        assert "mailgun" in services
        assert "huggingface" in services

    def test_filter_by_services(self):
        detector = KeyDetector(services=["aws", "github"])
        assert set(detector.supported_services) == {"aws", "github"}

    def test_filter_unknown_service_returns_empty(self):
        detector = KeyDetector(services=["nonexistent_service_xyz"])
        assert detector.supported_services == []


class TestDetectSingle:
    """Test single key classification."""

    @pytest.mark.parametrize(
        "key,expected_service",
        [
            ("AKIAIOSFODNN7EXAMPLE", "aws"),
            ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZab", "github"),
            ("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZab", "github"),
            ("github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github"),
            ("sk_live_ABCDEFGHIJKLMNOPQRSTUV", "stripe"),
            ("sk_test_ABCDEFGHIJKLMNOPQRSTUV", "stripe"),
            ("xoxb-" + "1" * 10 + "-" + "a" * 24, "slack"),
            ("xoxp-" + "1" * 10 + "-" + "a" * 24, "slack"),
            ("SG." + "a" * 22 + "." + "A" * 43, "sendgrid"),
            ("SK" + "0a" * 16, "twilio"),
            ("1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi", "telegram"),
            ("dop_v1_" + "a" * 64, "digitalocean"),
            ("key-" + "a" * 32, "mailgun"),
            ("hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabc", "huggingface"),
        ],
    )
    def test_known_patterns(self, key, expected_service):
        detector = KeyDetector()
        result = detector.detect_single(key)
        assert result is not None, f"Expected {expected_service} but got None for key: {key[:12]}..."
        assert result.service == expected_service

    def test_unknown_key_returns_none(self):
        detector = KeyDetector()
        result = detector.detect_single("this_is_not_an_api_key_at_all")
        assert result is None

    def test_empty_string_returns_none(self):
        detector = KeyDetector()
        result = detector.detect_single("")
        assert result is None

    def test_whitespace_stripped(self):
        detector = KeyDetector()
        result = detector.detect_single("  AKIAIOSFODNN7EXAMPLE  ")
        assert result is not None
        assert result.service == "aws"


class TestDetectInText:
    """Test multi-key detection in text blocks."""

    def test_finds_multiple_keys_in_text(self):
        text = """
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZab
        some random text here
        """
        detector = KeyDetector()
        results = detector.detect_in_text(text)
        assert len(results) == 2
        services = {r.service for r in results}
        assert services == {"aws", "github"}

    def test_deduplicates_same_key(self):
        text = """
        KEY=AKIAIOSFODNN7EXAMPLE
        ALSO=AKIAIOSFODNN7EXAMPLE
        """
        detector = KeyDetector()
        results = detector.detect_in_text(text)
        assert len(results) == 1

    def test_line_numbers_tracked(self):
        text = "line1\nAKIAIOSFODNN7EXAMPLE\nline3"
        detector = KeyDetector()
        results = detector.detect_in_text(text)
        assert len(results) == 1
        assert results[0].line_number == 2

    def test_source_file_passed_through(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        detector = KeyDetector()
        results = detector.detect_in_text(text, source_file="test.env")
        assert results[0].source_file == "test.env"

    def test_empty_text_returns_empty(self):
        detector = KeyDetector()
        assert detector.detect_in_text("") == []

    def test_anthropic_key_not_double_detected_as_openai(self):
        """Anthropic keys start with sk-ant- which also matches sk- pattern."""
        text = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        detector = KeyDetector()
        results = detector.detect_in_text(text)
        # Should detect as anthropic, not openai
        services = [r.service for r in results]
        assert "anthropic" in services
        # The openai pattern is suppressed for sk-ant- prefixed keys
        assert services.count("openai") == 0


class TestDetectBatch:
    """Test batch key classification."""

    def test_batch_classifies_multiple_keys(self):
        keys = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZab",
            "not_a_real_key",
        ]
        detector = KeyDetector()
        results = detector.detect_batch(keys)
        # Only recognized keys should be returned
        assert len(results) == 2

    def test_batch_empty_list(self):
        detector = KeyDetector()
        assert detector.detect_batch([]) == []


class TestDetectedKey:
    """Test DetectedKey dataclass methods."""

    def test_masked_hides_key(self):
        dk = DetectedKey(
            raw_value="AKIAIOSFODNN7EXAMPLE",
            service="aws",
            pattern_name="AWS Access Key ID",
        )
        masked = dk.masked(6)
        assert masked.startswith("AKIAIO")
        assert "*" in masked
        assert len(masked) == len(dk.raw_value)

    def test_masked_short_key_not_masked(self):
        dk = DetectedKey(raw_value="short", service="x", pattern_name="x")
        assert dk.masked(6) == "short"

    def test_short_id(self):
        dk = DetectedKey(
            raw_value="AKIAIOSFODNN7EXAMPLE",
            service="aws",
            pattern_name="AWS Access Key ID",
        )
        assert dk.short_id() == "aws:AKIAIОСF..."[:13] or dk.short_id().startswith("aws:")


class TestHelperFunctions:
    """Test module-level helper functions."""

    def test_get_all_patterns_returns_list(self):
        patterns = get_all_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) >= 12
        assert all(isinstance(p, KeyPattern) for p in patterns)

    def test_get_supported_services(self):
        services = get_supported_services()
        assert "aws" in services
        assert "mailgun" in services
        assert "huggingface" in services
