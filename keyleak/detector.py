"""Key type detection engine using regex patterns.

Each pattern is mapped to a service name and validator module.
The detector scans arbitrary text and extracts potential API keys
along with their likely service origin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class DetectedKey:
    """Represents a single detected API key with metadata."""

    raw_value: str
    service: str
    pattern_name: str
    confidence: float = 1.0
    line_number: int | None = None
    source_file: str | None = None

    def masked(self, visible: int = 6) -> str:
        """Return a masked version of the key for safe display."""
        if len(self.raw_value) <= visible:
            return self.raw_value
        return self.raw_value[:visible] + "*" * (len(self.raw_value) - visible)

    def short_id(self) -> str:
        """Return a short identifier for the key."""
        return f"{self.service}:{self.raw_value[:8]}..."


@dataclass
class KeyPattern:
    """Defines a regex pattern for detecting a specific type of API key."""

    service: str
    pattern: re.Pattern
    description: str
    validator_module: str
    prefix_hint: str = ""
    min_length: int = 10
    max_length: int = 500

    def matches(self, text: str) -> list[str]:
        """Find all matches of this pattern in the given text."""
        results = []
        for match in self.pattern.finditer(text):
            key = match.group(0)
            if self.min_length <= len(key) <= self.max_length:
                results.append(key)
        return results


# --------------------------------------------------------------------------- #
# Pattern registry
# --------------------------------------------------------------------------- #

_PATTERNS: list[KeyPattern] = [
    KeyPattern(
        service="aws",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        description="AWS Access Key ID",
        validator_module="keyleak.validators.aws",
        prefix_hint="AKIA",
        min_length=20,
        max_length=20,
    ),
    KeyPattern(
        service="openai",
        pattern=re.compile(r"sk-[A-Za-z0-9_-]{20,120}"),
        description="OpenAI API Key",
        validator_module="keyleak.validators.openai_key",
        prefix_hint="sk-",
        min_length=20,
        max_length=200,
    ),
    KeyPattern(
        service="anthropic",
        pattern=re.compile(r"sk-ant-[A-Za-z0-9_-]{20,120}"),
        description="Anthropic API Key",
        validator_module="keyleak.validators.anthropic_key",
        prefix_hint="sk-ant-",
        min_length=20,
        max_length=200,
    ),
    KeyPattern(
        service="github",
        pattern=re.compile(r"(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,255}"),
        description="GitHub Personal Access Token",
        validator_module="keyleak.validators.github_key",
        prefix_hint="ghp_/gho_/github_pat_",
        min_length=20,
        max_length=300,
    ),
    KeyPattern(
        service="stripe",
        pattern=re.compile(r"(?:sk_live_|sk_test_)[A-Za-z0-9]{20,60}"),
        description="Stripe Secret Key",
        validator_module="keyleak.validators.stripe_key",
        prefix_hint="sk_live_/sk_test_",
        min_length=20,
        max_length=100,
    ),
    KeyPattern(
        service="slack",
        pattern=re.compile(r"xox[bp]-[0-9A-Za-z\-]{20,200}"),
        description="Slack Bot/User Token",
        validator_module="keyleak.validators.slack_key",
        prefix_hint="xoxb-/xoxp-",
        min_length=20,
        max_length=250,
    ),
    KeyPattern(
        service="sendgrid",
        pattern=re.compile(r"SG\.[A-Za-z0-9_-]{20,70}\.[A-Za-z0-9_-]{20,70}"),
        description="SendGrid API Key",
        validator_module="keyleak.validators.sendgrid_key",
        prefix_hint="SG.",
        min_length=40,
        max_length=200,
    ),
    KeyPattern(
        service="twilio",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
        description="Twilio API Key",
        validator_module="keyleak.validators.twilio_key",
        prefix_hint="SK",
        min_length=34,
        max_length=34,
    ),
    KeyPattern(
        service="telegram",
        pattern=re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
        description="Telegram Bot Token",
        validator_module="keyleak.validators.telegram_key",
        prefix_hint="digits:",
        min_length=40,
        max_length=60,
    ),
    KeyPattern(
        service="digitalocean",
        pattern=re.compile(r"dop_v1_[a-f0-9]{64}"),
        description="DigitalOcean Personal Access Token",
        validator_module="keyleak.validators.digitalocean_key",
        prefix_hint="dop_v1_",
        min_length=71,
        max_length=71,
    ),
    KeyPattern(
        service="mailgun",
        pattern=re.compile(r"key-[a-f0-9]{32}"),
        description="Mailgun Private API Key",
        validator_module="keyleak.validators.mailgun_key",
        prefix_hint="key-",
        min_length=36,
        max_length=36,
    ),
    KeyPattern(
        service="huggingface",
        pattern=re.compile(r"hf_[A-Za-z0-9]{20,60}"),
        description="Hugging Face Access Token",
        validator_module="keyleak.validators.huggingface_key",
        prefix_hint="hf_",
        min_length=23,
        max_length=63,
    ),
]


class KeyDetector:
    """Scans text for potential API keys using registered patterns.

    The detector iterates through all known patterns and returns
    DetectedKey objects for each match. When a key matches multiple
    patterns, the most specific (longest prefix) match wins.
    """

    def __init__(self, services: list[str] | None = None):
        """Initialize detector with optional service filter.

        Args:
            services: If provided, only detect keys for these services.
        """
        if services:
            self._patterns = [p for p in _PATTERNS if p.service in services]
        else:
            self._patterns = list(_PATTERNS)

    @property
    def supported_services(self) -> list[str]:
        """Return list of supported service names."""
        return [p.service for p in self._patterns]

    def detect_in_text(
        self,
        text: str,
        source_file: str | None = None,
    ) -> list[DetectedKey]:
        """Scan raw text for API keys.

        Args:
            text: The text to scan.
            source_file: Optional filename for context.

        Returns:
            List of DetectedKey objects found in the text.
        """
        results: list[DetectedKey] = []
        seen: set = set()
        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for pattern in self._patterns:
                matches = pattern.matches(line)
                for raw_key in matches:
                    if raw_key in seen:
                        continue
                    # If key matches anthropic AND openai, prefer anthropic (more specific)
                    if pattern.service == "openai" and raw_key.startswith("sk-ant-"):
                        continue
                    seen.add(raw_key)
                    results.append(
                        DetectedKey(
                            raw_value=raw_key,
                            service=pattern.service,
                            pattern_name=pattern.description,
                            line_number=line_idx,
                            source_file=source_file,
                        )
                    )

        return results

    def detect_in_file(self, filepath: str) -> list[DetectedKey]:
        """Scan a file for API keys.

        Args:
            filepath: Path to the file to scan.

        Returns:
            List of DetectedKey objects found.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
        """
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        return self.detect_in_text(content, source_file=filepath)

    def detect_single(self, key: str) -> DetectedKey | None:
        """Classify a single key string.

        Args:
            key: The raw key value to classify.

        Returns:
            A DetectedKey if it matches a known pattern, else None.
        """
        key = key.strip()
        for pattern in self._patterns:
            if pattern.pattern.fullmatch(key) or pattern.matches(key):
                matches = pattern.matches(key)
                if matches:
                    return DetectedKey(
                        raw_value=key,
                        service=pattern.service,
                        pattern_name=pattern.description,
                    )
        return None

    def detect_batch(self, keys: list[str]) -> list[DetectedKey]:
        """Classify a batch of key strings.

        Args:
            keys: List of raw key values.

        Returns:
            List of DetectedKey objects for keys that match known patterns.
        """
        results = []
        for key in keys:
            detected = self.detect_single(key)
            if detected is not None:
                results.append(detected)
        return results


def get_all_patterns() -> list[KeyPattern]:
    """Return a copy of all registered patterns."""
    return list(_PATTERNS)


def get_supported_services() -> list[str]:
    """Return list of all supported service names."""
    return [p.service for p in _PATTERNS]
