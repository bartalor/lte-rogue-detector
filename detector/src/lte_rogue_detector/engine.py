"""Streaming detector engine.

One pass over unassigned messages in ts order. Per message we:

  1. Lazily close any open sessions whose gap to *this* message exceeded
     the threshold (they fire `on_session_close` for every rule).
  2. Resolve / create the session for this message's eNB-UE-S1AP-ID.
  3. Stamp `session_id` onto the message.
  4. Feed the message to every rule's `observe`, collecting alerts.
  5. If the message is a DetachRequest, mark the session
     close-on-next-message (a fresh row with the same eNB ID must start
     a new session even within the gap).

At end-of-stream every still-open session is closed.

This subsumes the old two-stage `sessionize() -> run_rules()` pipeline.
The driver is the same in both batch (replay all unassigned rows) and
watch (poll-and-replay) modes; the difference is only how often it runs.
"""
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, NamedTuple

from .db import transaction
from .rules import ALL_RULES
from .rules.base import Alert, StreamingRule


DEFAULT_GAP = timedelta(seconds=30)


@dataclass
class Stats:
    sessions_created: int = 0
    messages_assigned: int = 0
    messages_skipped_no_enb_id: int = 0
    alerts_inserted: int = 0


class _OpenSession(NamedTuple):
    session_id: int
    last_ts: datetime
    closed_by_detach: bool


@dataclass
class _SessionRuleStates:
    # rule.name -> per-rule state dict for this session
    by_rule: dict[str, dict[str, Any]] = field(default_factory=dict)

    def for_rule(self, name: str) -> dict[str, Any]:
        return self.by_rule.setdefault(name, {})


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _format_ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def process_stream(
    conn: sqlite3.Connection,
    rules: list[StreamingRule] | None = None,
    gap: timedelta = DEFAULT_GAP,
) -> Stats:
    rules = rules if rules is not None else ALL_RULES
    stats = Stats()

    rows = conn.execute(
        "SELECT * FROM messages WHERE session_id IS NULL"
        " ORDER BY ts, message_id"
    ).fetchall()
    if not rows:
        return stats

    open_sessions: dict[int, _OpenSession] = {}
    rule_states: dict[int, _SessionRuleStates] = {}
    assignments: list[tuple[int, int]] = []  # (session_id, message_id)
    pending_alerts: list[tuple[int, int | None, str, int, str]] = []
    last_ts_by_session: dict[int, datetime] = {}

    def emit_alerts(session_id: int, alerts: Iterable[Alert]) -> None:
        for a in alerts:
            pending_alerts.append(
                (session_id, a.trigger_message_id, a.rule_name,
                 a.severity, a.detail)
            )

    def close_session(enb_id: int) -> None:
        sess = open_sessions.pop(enb_id)
        states = rule_states.pop(sess.session_id)
        for rule in rules:
            emit_alerts(
                sess.session_id,
                rule.on_session_close(states.for_rule(rule.name)),
            )

    with transaction(conn):
        for r in rows:
            enb_id = r["enb_ue_s1ap_id"]
            if enb_id is None:
                stats.messages_skipped_no_enb_id += 1
                continue

            ts = _parse_ts(r["ts"])
            current = open_sessions.get(enb_id)
            reuse = (
                current is not None
                and not current.closed_by_detach
                and ts - current.last_ts <= gap
            )

            if current is not None and not reuse:
                # gap exceeded or detach previously seen — close before
                # starting the new one.
                close_session(enb_id)

            if reuse:
                session_id = current.session_id
            else:
                cur = conn.execute(
                    "INSERT INTO sessions (enb_ue_s1ap_id, started_at)"
                    " VALUES (?, ?)",
                    (enb_id, r["ts"]),
                )
                session_id = cur.lastrowid
                stats.sessions_created += 1
                rule_states[session_id] = _SessionRuleStates()

            states = rule_states[session_id]
            for rule in rules:
                emit_alerts(
                    session_id,
                    rule.observe(r, states.for_rule(rule.name)),
                )

            closed_by_detach = r["nas_msg_type"] == "DetachRequest"
            open_sessions[enb_id] = _OpenSession(session_id, ts, closed_by_detach)
            last_ts_by_session[session_id] = ts
            assignments.append((session_id, r["message_id"]))
            stats.messages_assigned += 1

        # Close every still-open session at end of stream.
        for enb_id in list(open_sessions.keys()):
            close_session(enb_id)

        if assignments:
            conn.executemany(
                "UPDATE messages SET session_id = ? WHERE message_id = ?",
                assignments,
            )
            conn.executemany(
                "UPDATE sessions SET ended_at = ? WHERE session_id = ?",
                [(_format_ts(ts), sid) for sid, ts in last_ts_by_session.items()],
            )

        if pending_alerts:
            conn.executemany(
                "INSERT INTO alerts"
                " (session_id, trigger_message_id, rule_name, severity, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                pending_alerts,
            )
            stats.alerts_inserted = len(pending_alerts)

    return stats
