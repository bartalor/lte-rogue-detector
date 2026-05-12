"""Run detection rules over every session and persist their alerts."""
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from .db import transaction
from .rules import ALL_RULES
from .rules.base import Alert, Rule, Session


@dataclass
class EngineStats:
    sessions_evaluated: int
    alerts_inserted: int


def _load_sessions(conn: sqlite3.Connection) -> Iterable[Session]:
    sess_rows = conn.execute(
        "SELECT session_id, enb_ue_s1ap_id, mme_ue_s1ap_id, started_at, ended_at"
        " FROM sessions ORDER BY started_at, session_id"
    ).fetchall()
    for s in sess_rows:
        msgs = conn.execute(
            "SELECT message_id, session_id, ts, direction, nas_msg_type,"
            " identity_type, eea_selected, eia_selected, ue_eea_caps,"
            " ue_eia_caps, emm_cause, enb_ue_s1ap_id, mme_ue_s1ap_id"
            " FROM messages WHERE session_id = ?"
            " ORDER BY ts, message_id",
            (s["session_id"],),
        ).fetchall()
        yield Session(
            session_id=s["session_id"],
            enb_ue_s1ap_id=s["enb_ue_s1ap_id"],
            mme_ue_s1ap_id=s["mme_ue_s1ap_id"],
            started_at=s["started_at"],
            ended_at=s["ended_at"],
            messages=msgs,
        )


def run_rules(
    conn: sqlite3.Connection, rules: list[Rule] | None = None
) -> EngineStats:
    rules = rules if rules is not None else ALL_RULES
    stats = EngineStats(0, 0)
    pending: list[tuple[int, int | None, str, int, str]] = []

    for session in _load_sessions(conn):
        stats.sessions_evaluated += 1
        for rule in rules:
            for alert in rule.evaluate(session):
                pending.append(
                    (
                        session.session_id,
                        alert.trigger_message_id,
                        alert.rule_name,
                        alert.severity,
                        alert.detail,
                    )
                )

    if pending:
        with transaction(conn):
            conn.executemany(
                "INSERT INTO alerts"
                " (session_id, trigger_message_id, rule_name, severity, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                pending,
            )
        stats.alerts_inserted = len(pending)

    return stats
