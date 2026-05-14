"""Rule interface shared by all detection rules.

Rules are streaming consumers: the engine feeds them one message at a time
in ts order, scoped to a single session, and tells them when the session
closes. Each rule gets its own per-session `state` dict to carry whatever
it needs across messages — the engine never inspects it.
"""
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable, Protocol


@dataclass(frozen=True)
class Alert:
    rule_name: str
    severity: int
    trigger_message_id: int | None
    detail: str


class StreamingRule(Protocol):
    name: str
    severity: int

    def observe(
        self, msg: sqlite3.Row, state: dict[str, Any]
    ) -> Iterable[Alert]: ...

    def on_session_close(
        self, state: dict[str, Any]
    ) -> Iterable[Alert]: ...
