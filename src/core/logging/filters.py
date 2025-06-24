"""PII (Personally Identifiable Information) redaction filters for logging.

This module provides filters to detect and redact sensitive personal information
from log messages to ensure GDPR/DSGVO compliance and data protection.

Author: Mike Berndt <berndt.mike@gmail.com>
Date: 2025-06-20
"""

import hashlib
import re
from dataclasses import dataclass
from re import Pattern
from typing import Any


@dataclass
class RedactionRule:
    """Configuration for a PII redaction rule."""

    name: str
    pattern: Pattern[str]
    replacement: str = "[REDACTED]"
    hash_value: bool = False
    description: str = ""


class PIIRedactionFilter:
    """Filter to detect and redact PII from log messages.

    This filter uses regex patterns to identify and redact various types of
    personally identifiable information including:
    - Email addresses
    - IP addresses
    - Phone numbers
    - Credit card numbers
    - Social security numbers
    - API keys and tokens

    The filter can either replace values with a placeholder or hash them
    for pseudonymization (allowing correlation without exposing actual data).
    """

    def __init__(
        self,
        custom_rules: list[RedactionRule] | None = None,
        hash_salt: str = "nai-v3-logging",
        enable_hashing: bool = True,
    ) -> None:
        """Initialize the PII redaction filter.

        Args:
        ----
            custom_rules: Additional redaction rules to apply
            hash_salt: Salt for hashing PII values
            enable_hashing: Whether to hash values or just redact

        """
        self.hash_salt = hash_salt
        self.enable_hashing = enable_hashing
        self.rules = self._get_default_rules()

        if custom_rules:
            self.rules.extend(custom_rules)

    def _get_default_rules(self) -> list[RedactionRule]:
        """Get default PII redaction rules.

        IMPORTANT: Order matters! More specific patterns should come before
        general patterns to avoid false positives.
        """
        return [
            # JWT tokens (very specific, check first)
            RedactionRule(
                name="jwt",
                pattern=re.compile(
                    r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
                ),
                replacement="[JWT_TOKEN]",
                hash_value=False,
                description="JWT tokens",
            ),
            # Credit card numbers (check before phone numbers!)
            RedactionRule(
                name="credit_card",
                pattern=re.compile(
                    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
                    r"5[1-5][0-9]{14}|"  # Mastercard
                    r"3[47][0-9]{13}|"  # American Express
                    r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"  # Diners Club
                    r"6(?:011|5[0-9]{2})[0-9]{12}|"  # Discover
                    r"(?:2131|1800|35\d{3})\d{11})\b"  # JCB
                ),
                replacement="[CREDIT_CARD]",
                hash_value=False,
                description="Credit card numbers",
            ),
            # Social Security Numbers (US) - specific format
            RedactionRule(
                name="ssn",
                pattern=re.compile(
                    r"\b(?!000|666|9\d{2})\d{3}[-.\s]?(?!00)\d{2}[-.\s]?(?!0000)\d{4}\b"
                ),
                replacement="[SSN]",
                hash_value=False,
                description="Social Security Numbers",
            ),
            # Email addresses
            RedactionRule(
                name="email",
                pattern=re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                ),
                replacement="[EMAIL]",
                hash_value=True,
                description="Email addresses",
            ),
            # IP addresses (IPv4)
            RedactionRule(
                name="ipv4",
                pattern=re.compile(
                    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
                ),
                replacement="[IPv4]",
                hash_value=True,
                description="IPv4 addresses",
            ),
            # IP addresses (IPv6)
            RedactionRule(
                name="ipv6",
                pattern=re.compile(
                    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                    r"([0-9a-fA-F]{1,4}:){1,7}:|"
                    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                    r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                    r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
                    r"::(ffff(:0{1,4}){0,1}:){0,1}"
                    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
                    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
                    r"([0-9a-fA-F]{1,4}:){1,4}:"
                    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
                    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
                ),
                replacement="[IPv6]",
                hash_value=True,
                description="IPv6 addresses",
            ),
            # Standalone API Keys with common prefixes
            RedactionRule(
                name="api_key_prefix",
                pattern=re.compile(
                    r"\b(sk|pk|api|key|token|pat|gho|ghs|ghp|ghu)[-_]"
                    r"[a-zA-Z0-9]{20,}\b"
                ),
                replacement="[API_KEY]",
                hash_value=False,
                description="API keys with common prefixes",
            ),
            # API Keys (generic patterns)
            RedactionRule(
                name="api_key",
                pattern=re.compile(
                    r"(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)"
                    r'["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'
                ),
                replacement="[API_KEY]",
                hash_value=False,
                description="API keys and tokens",
            ),
            # Bearer tokens in Authorization headers
            RedactionRule(
                name="bearer_token",
                pattern=re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
                replacement="Bearer [TOKEN]",
                hash_value=False,
                description="Bearer tokens",
            ),
            # Phone numbers (various formats) - LAST because it's the most general
            RedactionRule(
                name="phone",
                pattern=re.compile(
                    r"(?:\+?[1-9]\d{0,2}[\s.-]?)?"  # Optional country code
                    r"(?:\(\d{1,4}\)|(?<!\d)\d{1,4}(?!\d))"  # Area code or first digits
                    r"[\s.-]?"  # Optional separator
                    r"\d{1,4}"  # Middle digits
                    r"[\s.-]?"  # Optional separator
                    r"\d{3,4}"  # Last digits
                    r"(?!\d)"  # Not followed by more digits
                ),
                replacement="[PHONE]",
                hash_value=False,
                description="Phone numbers",
            ),
        ]

    def _hash_value(self, value: str) -> str:
        """Create a deterministic hash of a value for pseudonymization.

        Args:
        ----
            value: The value to hash

        Returns:
        -------
            A shortened hash of the value

        """
        hash_input = f"{self.hash_salt}:{value}".encode()
        hash_value = hashlib.sha256(hash_input).hexdigest()
        # Return first 8 characters for readability
        return hash_value[:8]

    def redact_string(self, text: str) -> tuple[str, dict[str, int]]:
        """Redact PII from a string.

        Args:
        ----
            text: The text to redact PII from

        Returns:
        -------
            Tuple of (redacted_text, statistics)

        """
        import re
        
        # Step 1: Find and temporarily mask protected patterns to avoid false positives
        protected_patterns = [
            # UUIDs
            (r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', 'UUID'),
            # ISO timestamps and time formats
            (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', 'TIMESTAMP'),
            (r'\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b', 'TIME_FORMAT'),
            # Decimal numbers with units (measurements, durations)
            (r'\b\d+\.\d+(?:s|ms|%|MB|KB|GB|Hz|MHz|GHz)\b', 'DECIMAL_WITH_UNIT'),
            # Pi and other mathematical constants (specific patterns)
            (r'\b3\.14159\b', 'MATH_CONSTANT'),
            (r'\b2\.71828\b', 'MATH_CONSTANT'),
            # SQL parameter placeholders
            (r'\$\d+::', 'SQL_PARAM'),
        ]
        
        protected_map = {}
        redacted = text
        placeholder_counter = 0
        
        # Replace protected patterns with temporary placeholders
        for pattern, pattern_type in protected_patterns:
            matches = list(re.finditer(pattern, redacted))
            for match in reversed(matches):
                start, end = match.span()
                protected_value = match.group()
                placeholder = f"__PROTECTED_{pattern_type}_{placeholder_counter}__"
                protected_map[placeholder] = protected_value
                redacted = redacted[:start] + placeholder + redacted[end:]
                placeholder_counter += 1
        
        # Step 2: Apply normal PII redaction rules
        stats: dict[str, int] = {}

        for rule in self.rules:
            matches = list(rule.pattern.finditer(redacted))
            stats[rule.name] = len(matches)

            for match in reversed(matches):  # Process in reverse to maintain positions
                start, end = match.span()
                matched_value = match.group()

                if rule.hash_value and self.enable_hashing:
                    # For patterns with groups (like api_key), get the value group
                    if match.groups() and match.groups()[-1] is not None:
                        # Get the last group which typically contains the actual value
                        value_to_hash = match.groups()[-1]
                        # Replace only the value part, keep the key part
                        prefix = matched_value[: matched_value.find(value_to_hash)]
                        replacement = f"{prefix}{rule.replacement}:{self._hash_value(value_to_hash)}"
                    else:
                        replacement = (
                            f"{rule.replacement}:{self._hash_value(matched_value)}"
                        )
                else:
                    replacement = rule.replacement

                redacted = redacted[:start] + replacement + redacted[end:]

        # Step 3: Restore protected patterns from placeholders
        for placeholder, protected_value in protected_map.items():
            redacted = redacted.replace(placeholder, protected_value)

        # Aggregate api_key_prefix stats into api_key for compatibility
        if "api_key_prefix" in stats:
            stats["api_key"] = stats.get("api_key", 0) + stats.pop("api_key_prefix")

        return redacted, stats

    def redact_dict(
        self, data: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, int]]:
        """Recursively redact PII from a dictionary.

        Args:
        ----
            data: The dictionary to redact PII from

        Returns:
        -------
            Tuple of (redacted_dict, statistics)

        """
        redacted: dict[str, Any] = {}
        total_stats: dict[str, int] = {}

        for key, value in data.items():
            # Redact the key itself
            redacted_key, key_stats = self.redact_string(str(key))
            self._merge_stats(total_stats, key_stats)

            # Redact the value
            if isinstance(value, str):
                redacted_value, value_stats = self.redact_string(value)
                self._merge_stats(total_stats, value_stats)
                redacted[redacted_key] = redacted_value
            elif isinstance(value, dict):
                redacted_dict_value, value_stats = self.redact_dict(value)
                self._merge_stats(total_stats, value_stats)
                redacted[redacted_key] = redacted_dict_value
            elif isinstance(value, list):
                redacted_list: list[Any] = []
                for item in value:
                    if isinstance(item, str):
                        redacted_item, item_stats = self.redact_string(item)
                        self._merge_stats(total_stats, item_stats)
                        redacted_list.append(redacted_item)
                    elif isinstance(item, dict):
                        redacted_dict_item, item_stats = self.redact_dict(item)
                        self._merge_stats(total_stats, item_stats)
                        redacted_list.append(redacted_dict_item)
                    else:
                        redacted_list.append(item)
                redacted[redacted_key] = redacted_list
            else:
                redacted[redacted_key] = value

        return redacted, total_stats

    def _merge_stats(self, total: dict[str, int], new: dict[str, int]) -> None:
        """Merge statistics dictionaries."""
        for key, value in new.items():
            total[key] = total.get(key, 0) + value

    def filter_event(self, event_data: dict[str, Any]) -> dict[str, Any]:
        """Filter PII from a log event dictionary.

        This is a convenience method for middleware that just needs
        the filtered data without statistics.

        Args:
        ----
            event_data: Dictionary containing log event data

        Returns:
        -------
            Filtered dictionary with PII redacted

        """
        filtered_data, _ = self.redact_dict(event_data)
        return filtered_data

    def __call__(
        self, logger: Any, name: str, event_dict: dict[str, Any]
    ) -> dict[str, Any]:
        """Process log event dict for structlog integration.

        This method allows the filter to be used as a structlog processor.
        """
        # Redact the entire event dictionary
        redacted_dict, stats = self.redact_dict(event_dict)

        # Add redaction statistics if any PII was found
        if any(stats.values()):
            redacted_dict["_pii_redacted"] = stats

        return redacted_dict


def create_pii_filter(**kwargs: Any) -> PIIRedactionFilter:
    """Create a PII redaction filter.

    Args:
    ----
        **kwargs: Arguments to pass to PIIRedactionFilter

    Returns:
    -------
        Configured PIIRedactionFilter instance

    """
    return PIIRedactionFilter(**kwargs)
