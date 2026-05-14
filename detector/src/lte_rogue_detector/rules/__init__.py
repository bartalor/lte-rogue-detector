"""Pluggable detection rules.

A rule is a streaming consumer: the engine feeds it one message at a time
in ts order, scoped to a single session, plus a session-close callback.
Adding a new rule is two steps: write the class, append it to `ALL_RULES`.
"""
from .aka_skipped_or_failed import AkaSkippedOrFailedRule
from .base import Alert, StreamingRule
from .imsi_cleartext_with_guti import ImsiCleartextWithGutiRule


ALL_RULES: list[StreamingRule] = [
    ImsiCleartextWithGutiRule(),
    AkaSkippedOrFailedRule(),
]
