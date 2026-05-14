"""Run detection rules over every session and persist their alerts."""
import sqlite3
from dataclasses import dataclass
from itertools import groupby
from typing import Iterable

from .db import transaction
from .rules import ALL_RULES
from .rules.base import Alert, Rule, Session


@dataclass
class EngineStats:
    sessions_evaluated: int
    alerts_inserted: int


def _load_sessions(conn: sqlite3.Connection) -> Iterable[Session]:
    # One round-trip: sessions LEFT JOIN messages, grouped in Python.
    rows = conn.execute(
        "SELECT s.session_id AS s_session_id,"
        " s.enb_ue_s1ap_id AS s_enb_ue_s1ap_id,"
        " s.mme_ue_s1ap_id AS s_mme_ue_s1ap_id,"
        " s.started_at AS s_started_at,"
        " s.ended_at AS s_ended_at,"
        " m.message_id, m.session_id, m.ts, m.direction, m.nas_msg_type,"
        " m.identity_type, m.eea_selected, m.eia_selected, m.ue_eea_caps,"
        " m.ue_eia_caps, m.emm_cause, m.enb_ue_s1ap_id, m.mme_ue_s1ap_id"
        " FROM sessions s LEFT JOIN messages m USING (session_id)"
        " ORDER BY s.started_at, s.session_id, m.ts, m.message_id"
    ).fetchall()
    for _, group in groupby(rows, key=lambda r: r["s_session_id"]):
        group = list(group)
        head = group[0]
        msgs = [r for r in group if r["message_id"] is not None]
        yield Session(
            session_id=head["s_session_id"],
            enb_ue_s1ap_id=head["s_enb_ue_s1ap_id"],
            mme_ue_s1ap_id=head["s_mme_ue_s1ap_id"],
            started_at=head["s_started_at"],
            ended_at=head["s_ended_at"],
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
