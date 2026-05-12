"""Rule interface shared by all detection rules."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Iterable, Protocol


@dataclass(frozen=True)
class Session:
    session_id: int
    enb_ue_s1ap_id: int
    mme_ue_s1ap_id: int | None
    started_at: str
    ended_at: str | None
    # Messages for the session, ordered by ts. Each is a sqlite3.Row.
    messages: list[sqlite3.Row]


@dataclass(frozen=True)
class Alert:
    rule_name: str
    severity: int
    trigger_message_id: int | None
    detail: str


class Rule(Protocol):
    name: str
    severity: int

    def evaluate(self, session: Session) -> Iterable[Alert]: ...
