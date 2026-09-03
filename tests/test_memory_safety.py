"""
tests/test_memory_safety.py — Shared memory safety firewall tests.
"""

from __future__ import annotations

from mnemos.config import MemorySafetyConfig
from mnemos.memory_safety import MemoryWriteFirewall


def test_firewall_blocks_secret_by_default() -> None:
    firewall = MemoryWriteFirewall(MemorySafetyConfig())
    decision = firewall.apply("api_key=supersecretvalue")
    assert decision.allowed is False
    assert "secret" in decision.reason.lower()


def test_firewall_redacts_pii_by_default() -> None:
    firewall = MemoryWriteFirewall(MemorySafetyConfig())
    decision = firewall.apply("Contact me at jane@example.com tomorrow")
    assert decision.allowed is True
    assert "REDACTED_EMAIL" in decision.content


def test_firewall_can_allow_all() -> None:
    firewall = MemoryWriteFirewall(
        MemorySafetyConfig(
            enabled=True,
            secret_action="allow",
            pii_action="allow",
        )
    )
    content = "api_key=abc123 and jane@example.com"
    decision = firewall.apply(content)
    assert decision.allowed is True
    assert decision.content == content


def test_firewall_does_not_redact_bare_digit_runs_as_phone() -> None:
    """Technical identifiers must survive the PII pass.

    The phone pattern once made every separator optional, so a bare run of
    ten digits matched and a ZFS hostid was stored as "[REDACTED_PHONE]".
    """
    firewall = MemoryWriteFirewall(MemorySafetyConfig())
    for content in (
        "active_zfs_hostid was 3486326916 at collection",
        "id 1234567890 appears here",
        "oldest xmin: 8354754 NextXID 4037591847",
        "BP 5.9.4-3259574 on //redline/r5.x",
        'pool id "10439569960022148193"',
        "pg_wal/000000010000008100000093",
        "gateway 10.96.146.254 fib 0",
        "Total Ram: 549542502400",
    ):
        decision = firewall.apply(content)
        assert decision.allowed is True
        assert decision.content == content, f"unexpectedly rewritten: {content}"


def test_firewall_still_redacts_real_phone_numbers() -> None:
    firewall = MemoryWriteFirewall(MemorySafetyConfig())
    for content in (
        "call 415-555-0132 today",
        "call 415.555.0132 today",
        "call 415 555 0132 today",
        "call (415) 555-0132 today",
        "call +1 415-555-0132 today",
    ):
        decision = firewall.apply(content)
        assert decision.allowed is True
        assert "REDACTED_PHONE" in decision.content, f"not redacted: {content}"


def test_firewall_does_not_redact_identifiers_as_credit_cards() -> None:
    """Numeric identifiers must survive the credit-card pass.

    The pattern nominates any bare run of 13-16 digits, so without the
    issuer-prefix plus Luhn gate it redacted ordinary identifiers. Note the
    epoch-millisecond case: it is Luhn-valid by chance, so a checksum-only
    gate is not sufficient on its own.
    """
    firewall = MemoryWriteFirewall(MemorySafetyConfig())
    for content in (
        'pool id "10439569960022148193"',
        "identifier 1234567890123456 here",
        "changelist 32595743259574 here",
        "ts 1756327200000 and 1756330800000",
        "vfs.zfs.arc_max=137385625600",
        "Total Ram: 549542502400",
    ):
        decision = firewall.apply(content)
        assert decision.allowed is True
        assert decision.content == content, f"unexpectedly rewritten: {content}"


def test_firewall_still_redacts_real_card_numbers() -> None:
    firewall = MemoryWriteFirewall(MemorySafetyConfig())
    for content in (
        "card 4111111111111111 on file",       # Visa 16
        "card 4111 1111 1111 1111 on file",    # Visa 16, spaced
        "card 5500-0000-0000-0004 on file",    # Mastercard 16, dashed
        "card 2223000048400011 on file",       # Mastercard 2-series
        "card 340000000000009 on file",        # Amex 15
        "card 4222222222222 on file",          # Visa 13
        "card 6011111111111117 on file",       # Discover 16
        "card 30569309025904 on file",         # Diners 14
    ):
        decision = firewall.apply(content)
        assert decision.allowed is True
        assert "REDACTED_CREDIT_CARD" in decision.content, f"not redacted: {content}"
