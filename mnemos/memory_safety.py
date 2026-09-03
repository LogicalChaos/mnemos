"""
mnemos/memory_safety.py — Shared memory write firewall.

Applies secret/PII policy checks and optional redaction across all long-term
memory write paths.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .config import MemorySafetyConfig

PatternCategory = Literal["secret", "pii"]


def _luhn_ok(digits: str) -> bool:
    """Return True if `digits` satisfies the Luhn checksum."""
    checksum = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _has_issuer_prefix(digits: str) -> bool:
    """Return True if `digits` opens with a real card issuer prefix at a
    length that issuer actually uses."""
    length = len(digits)
    head = int(digits[:4])
    if digits.startswith("4"):  # Visa
        return length in (13, 16, 19)
    if digits.startswith(("34", "37")):  # American Express
        return length == 15
    if digits.startswith(("51", "52", "53", "54", "55")) or 2221 <= head <= 2720:
        return length == 16  # Mastercard
    if digits.startswith(("65", "6011")) or digits[:3] in {
        "644", "645", "646", "647", "648", "649"
    }:
        return length in (16, 19)  # Discover
    if 3528 <= head <= 3589:  # JCB
        return length in (16, 19)
    if digits.startswith(("36", "38", "39")) or digits[:3] in {
        "300", "301", "302", "303", "304", "305"
    }:
        return length == 14  # Diners Club
    return False


def _is_card_number(candidate: str) -> bool:
    """Return True if `candidate` looks like a real payment card number.

    Payment cards are Luhn-valid by construction AND carry an issuer prefix,
    so requiring both is what separates a card from a numeric identifier of
    the same length. Luhn alone is not enough: roughly one in ten arbitrary
    digit runs passes it by chance, which is common enough to hit things like
    13-digit epoch-millisecond timestamps.
    """
    digits = "".join(char for char in candidate if char.isdigit())
    if not 13 <= len(digits) <= 19:
        return False
    return _has_issuer_prefix(digits) and _luhn_ok(digits)


@dataclass(frozen=True)
class MemorySafetyMatch:
    """A matched sensitive pattern found in content."""

    category: PatternCategory
    label: str
    count: int


@dataclass(frozen=True)
class MemorySafetyDecision:
    """Safety decision returned by the write firewall."""

    allowed: bool
    content: str
    reason: str
    matches: tuple[MemorySafetyMatch, ...]


class MemoryWriteFirewall:
    """Policy-driven safety checks for memory write content."""

    _PATTERNS: tuple[tuple[PatternCategory, str, re.Pattern[str]], ...] = (
        ("secret", "private_key", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
        ("secret", "aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("secret", "openai_key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
        ("secret", "github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
        (
            "secret",
            "credential_assignment",
            re.compile(
                r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization)\b\s*[:=]\s*\S+"
            ),
        ),
        (
            "pii",
            "email",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ),
        (
            "pii",
            "phone",
            # A phone number must carry punctuation, a country code, or
            # parentheses. The previous pattern made every separator optional,
            # so it also matched any bare run of 10 digits and silently
            # redacted technical identifiers (ZFS hostids, XIDs, build
            # numbers) as "[REDACTED_PHONE]".
            re.compile(
                r"(?<!\d)(?:"
                r"\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
                r"|\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}"
                r"|\d{3}[-.\s]\d{3}[-.\s]\d{4}"
                r")(?!\d)"
            ),
        ),
        (
            "pii",
            "ssn",
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        ),
        (
            "pii",
            "credit_card",
            # The regex only nominates candidates; `_is_card_number`
            # decides via issuer prefix plus Luhn checksum. Without
            # that gate this matches any bare run of 13-16 digits and redacts
            # numeric identifiers as "[REDACTED_CREDIT_CARD]".
            re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        ),
    )

    # Patterns whose matches must additionally pass a validator before they
    # count as a hit. Keyed by pattern label.
    _VALIDATORS: dict[str, Callable[[str], bool]] = {"credit_card": _is_card_number}

    def __init__(self, config: MemorySafetyConfig | None = None) -> None:
        self._config = config or MemorySafetyConfig()

    @property
    def config(self) -> MemorySafetyConfig:
        return self._config

    def apply(self, content: str) -> MemorySafetyDecision:
        """
        Apply safety policy to content.

        Returns a decision with allowed/block verdict and possibly redacted text.
        """
        if not self._config.enabled:
            return MemorySafetyDecision(
                allowed=True,
                content=content,
                reason="Memory safety disabled.",
                matches=(),
            )

        working = content
        matches: list[MemorySafetyMatch] = []

        for category, label, pattern in self._PATTERNS:
            validator = self._VALIDATORS.get(label)
            if validator is None:
                found = pattern.findall(working)
            else:
                found = [
                    match.group(0)
                    for match in pattern.finditer(working)
                    if validator(match.group(0))
                ]
            if not found:
                continue

            count = len(found)
            matches.append(
                MemorySafetyMatch(
                    category=category,
                    label=label,
                    count=count,
                )
            )
            action = self._action_for_category(category)
            if action == "block":
                return MemorySafetyDecision(
                    allowed=False,
                    content=content,
                    reason=f"Blocked {category} pattern: {label}.",
                    matches=tuple(matches),
                )
            if action == "redact":
                token = f"[REDACTED_{label.upper()}]"
                if validator is None:
                    working = pattern.sub(token, working)
                else:
                    working = pattern.sub(
                        lambda match: (
                            token if validator(match.group(0)) else match.group(0)
                        ),
                        working,
                    )

        if matches:
            return MemorySafetyDecision(
                allowed=True,
                content=working,
                reason="Applied safety policy.",
                matches=tuple(matches),
            )
        return MemorySafetyDecision(
            allowed=True,
            content=content,
            reason="No safety matches.",
            matches=(),
        )

    def _action_for_category(
        self, category: PatternCategory
    ) -> Literal["allow", "redact", "block"]:
        if category == "secret":
            return self._config.secret_action
        return self._config.pii_action
