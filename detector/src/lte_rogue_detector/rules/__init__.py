"""Pluggable detection rules.

A rule is a callable that takes a `Session` (its metadata row + the ordered
list of NAS messages) and yields `Alert` objects. Adding a new rule is two
steps: write the class, append it to `ALL_RULES`.
"""
from .aka_skipped_or_failed import AkaSkippedOrFailedRule
from .base import Alert, Rule, Session
from .imsi_cleartext_with_guti import ImsiCleartextWithGutiRule


ALL_RULES: list[Rule] = [
    ImsiCleartextWithGutiRule(),
    AkaSkippedOrFailedRule(),
]
