"""Group unassigned messages into sessions.

A session is one UE's attach / authentication / security-mode-command /
attach-complete (or TAU) procedure on a single eNB. We don't have the cell
identity yet, so the key is the eNB-UE-S1AP-ID alone. To handle the eNB
reusing the same temporary ID for a different UE later, we also break
sessions on:

  * a `DetachRequest` (procedure has clearly ended), or
  * a gap longer than `gap_seconds` between consecutive messages with the
    same eNB-UE-S1AP-ID.

The sessionizer is idempotent: it only looks at rows with `session_id IS
NULL`, so re-running after the sniffer appends new rows just sessionizes
the newcomers.
"""
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from .db import transaction


DEFAULT_GAP = timedelta(seconds=30)


@dataclass
class SessionizeStats:
    sessions_created: int
    messages_assigned: int
    messages_skipped_no_enb_id: int


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _format_ts(t: datetime) -> str:
    # Match the sniffer's wire shape: ISO 8601, always microseconds, trailing Z.
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sessionize(
    conn: sqlite3.Connection, gap: timedelta = DEFAULT_GAP
) -> SessionizeStats:
    rows = conn.execute(
        """
        SELECT message_id, ts, nas_msg_type, enb_ue_s1ap_id
        FROM messages
        WHERE session_id IS NULL
        ORDER BY ts, message_id
        """
    ).fetchall()

    stats = SessionizeStats(0, 0, 0)
    if not rows:
        return stats

    # Per-enb-id current open session: (session_id, last_ts, closed_by_detach).
    open_sessions: dict[int, tuple[int, datetime, bool]] = {}
    assignments: list[tuple[int, int]] = []  # (session_id, message_id)

    with transaction(conn):
        for r in rows:
            enb_id: Optional[int] = r["enb_ue_s1ap_id"]
            if enb_id is None:
                stats.messages_skipped_no_enb_id += 1
                continue

            ts = _parse_ts(r["ts"])
            open_ = open_sessions.get(enb_id)
            reuse = (
                open_ is not None
                and not open_[2]
                and ts - open_[1] <= gap
            )

            if reuse:
                session_id = open_[0]
            else:
                cur = conn.execute(
                    "INSERT INTO sessions (enb_ue_s1ap_id, started_at)"
                    " VALUES (?, ?)",
                    (enb_id, r["ts"]),
                )
                session_id = cur.lastrowid
                stats.sessions_created += 1

            closed = r["nas_msg_type"] == "DetachRequest"
            open_sessions[enb_id] = (session_id, ts, closed)
            assignments.append((session_id, r["message_id"]))
            stats.messages_assigned += 1

        conn.executemany(
            "UPDATE messages SET session_id = ? WHERE message_id = ?",
            assignments,
        )
        # Close every session we touched: ended_at = its last message's ts.
        # Sessions can re-open with a fresh row if more messages arrive later
        # (gap > threshold), so this is a per-pass closure, not permanent.
        end_updates = [
            (_format_ts(s[1]), s[0]) for s in open_sessions.values()
        ]
        conn.executemany(
            "UPDATE sessions SET ended_at = ? WHERE session_id = ?",
            end_updates,
        )

    return stats
