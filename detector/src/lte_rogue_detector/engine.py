"""Streaming detector engine.

One pass over unassigned messages in ts order. The orchestration in
`process_stream` delegates to three small collaborators:

  * `_Sessionizer` — owns the open-session map and the gap/detach
    lifecycle. Decides per row whether to reuse, close+open, or open.
    Persists the `sessions` row when one opens.
  * `_RuleRunner` — owns per-(session, rule) state. Fans `observe` and
    `on_session_close` out to every rule and yields alerts.
  * `_PassWriter` — buffers assignments, alerts, and per-session
    last-ts; flushes everything in one batch at end of pass.

This subsumes the old two-stage `sessionize() -> run_rules()` pipeline.
The driver is the same in both batch (replay all unassigned rows) and
watch (poll-and-replay) modes; the difference is only how often it runs.
"""
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Iterator, NamedTuple

from .db import transaction
from .rules import ALL_RULES
from .rules.base import Alert, MessageRow, StreamingRule


DEFAULT_GAP = timedelta(seconds=30)


@dataclass
class Stats:
    sessions_created: int = 0
    messages_assigned: int = 0
    messages_skipped_no_enb_id: int = 0
    messages_skipped_ambiguous_cell: int = 0
    alerts_inserted: int = 0


# A session key. cell identity (PLMN + 28-bit Cell ID) plus the per-eNB
# enb_ue_s1ap_id is what S1AP needs to uniquely identify a UE context:
# enb_ue_s1ap_id is only unique within an eNB (TS 36.413), so keying on it
# alone collapses two cells that happen to allocate the same value.
class _SessionKey(NamedTuple):
    plmn: str | None
    cell_id: int | None
    enb_ue_s1ap_id: int


class _OpenSession(NamedTuple):
    session_id: int
    last_ts: datetime
    closed_by_detach: bool
    mme_ue_s1ap_id: int | None


class _SessionEvent(NamedTuple):
    """What `_Sessionizer.step` decided for one row.

    `closed_id` is set if a previously-open session was closed to make
    room. `session_id` is the session this row belongs to. `opened` is
    True when `session_id` was newly created. `ambiguous` is True if a
    downlink row could not be matched to exactly one open session.
    """
    session_id: int | None
    closed_id: int | None
    opened: bool
    ambiguous: bool = False


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _format_ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class _Sessionizer:
    """Per-(cell, eNB-UE-ID) session lifecycle.

    Uplink rows arrive with a cell identity (EUTRAN-CGI is mandatory on
    InitialUEMessage and UplinkNASTransport) — those go straight into the
    open-sessions map keyed by (plmn, cell_id, enb_ue_s1ap_id).

    Downlink rows (DownlinkNASTransport) have no cell IE on the wire. We
    resolve them against open sessions sharing the same enb_ue_s1ap_id:
        - if mme_ue_s1ap_id is set on the row and any open session has
          the matching mme_ue_s1ap_id, use that;
        - else if there is exactly one open session with that enb_id,
          use it;
        - else the row is ambiguous and gets skipped.
    """

    def __init__(self, conn: sqlite3.Connection, gap: timedelta) -> None:
        self._conn = conn
        self._gap = gap
        self._open_sessions: dict[_SessionKey, _OpenSession] = {}

    def _resolve_key(self, row: MessageRow) -> _SessionKey | None:
        """Pick the open-session key this row belongs to, or None if ambiguous.

        An uplink row always identifies its own key directly. A downlink
        row (no cell IE on the wire) identifies a key by matching against
        currently-open sessions sharing its enb_ue_s1ap_id, disambiguating
        via mme_ue_s1ap_id when more than one is open.
        """
        enb_id = row["enb_ue_s1ap_id"]
        if row["cell_id"] is not None:
            return _SessionKey(row["plmn"], row["cell_id"], enb_id)

        candidates = [k for k in self._open_sessions if k.enb_ue_s1ap_id == enb_id]
        if not candidates:
            # No open session to attach to. A downlink-only row with no
            # prior uplink can't be placed; record it as its own key with
            # NULL cell so a subsequent uplink in the same UE context can
            # still be sessionized separately. This also covers messages
            # from a sniffer that couldn't extract EUTRAN-CGI.
            return _SessionKey(row["plmn"], row["cell_id"], enb_id)
        mme_id = row["mme_ue_s1ap_id"]
        if mme_id is not None:
            by_mme = [k for k in candidates
                      if self._open_sessions[k].mme_ue_s1ap_id == mme_id]
            if len(by_mme) == 1:
                return by_mme[0]
        if len(candidates) == 1:
            return candidates[0]
        return None

    def step(self, row: MessageRow, ts: datetime) -> _SessionEvent:
        key = self._resolve_key(row)
        if key is None:
            return _SessionEvent(None, None, False, ambiguous=True)

        current = self._open_sessions.get(key)
        reuse = (
            current is not None
            and not current.closed_by_detach
            and ts - current.last_ts <= self._gap
        )

        closed_id: int | None = None
        if current is not None and not reuse:
            closed_id = current.session_id
            del self._open_sessions[key]

        if reuse:
            session_id = current.session_id
            opened = False
            # Latch mme_ue_s1ap_id the first time we see it, so future
            # downlinks can disambiguate via it.
            mme_id = current.mme_ue_s1ap_id
            if mme_id is None and row["mme_ue_s1ap_id"] is not None:
                mme_id = row["mme_ue_s1ap_id"]
        else:
            cur = self._conn.execute(
                "INSERT INTO sessions"
                " (plmn, cell_id, enb_ue_s1ap_id, mme_ue_s1ap_id, started_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (key.plmn, key.cell_id, key.enb_ue_s1ap_id,
                 row["mme_ue_s1ap_id"], row["ts"]),
            )
            session_id = cur.lastrowid
            opened = True
            mme_id = row["mme_ue_s1ap_id"]

        closed_by_detach = row["nas_msg_type"] == "DetachRequest"
        self._open_sessions[key] = _OpenSession(
            session_id, ts, closed_by_detach, mme_id
        )
        return _SessionEvent(session_id, closed_id, opened)

    def drain(self) -> list[int]:
        ids = [s.session_id for s in self._open_sessions.values()]
        self._open_sessions.clear()
        return ids



@dataclass
class _RuleRunner:
    """Owns per-(session, rule) state and fans messages out to rules."""
    rules: list[StreamingRule]
    _states: dict[int, dict[str, dict[str, Any]]] = field(default_factory=dict)

    def on_open(self, session_id: int) -> None:
        self._states[session_id] = {r.name: {} for r in self.rules}

    def on_message(
        self, session_id: int, row: MessageRow
    ) -> Iterator[Alert]:
        states = self._states[session_id]
        for rule in self.rules:
            yield from rule.observe(row, states[rule.name])

    def on_close(self, session_id: int) -> Iterator[Alert]:
        states = self._states.pop(session_id)
        for rule in self.rules:
            yield from rule.on_session_close(states[rule.name])


class _PassWriter:
    """Buffers per-pass writes and flushes them in one batch."""

    def __init__(self) -> None:
        self._assignments: list[tuple[int, int]] = []
        self._alerts: list[tuple[int, int | None, str, int, str]] = []
        self._last_ts: dict[int, datetime] = {}

    def assign(self, session_id: int, message_id: int, ts: datetime) -> None:
        self._assignments.append((session_id, message_id))
        self._last_ts[session_id] = ts

    def add_alerts(self, session_id: int, alerts: Iterable[Alert]) -> None:
        for a in alerts:
            self._alerts.append(
                (session_id, a.trigger_message_id, a.rule_name,
                 a.severity, a.detail)
            )

    @property
    def alert_count(self) -> int:
        return len(self._alerts)

    def flush(self, conn: sqlite3.Connection) -> None:
        if self._assignments:
            conn.executemany(
                "UPDATE messages SET session_id = ? WHERE message_id = ?",
                self._assignments,
            )
            conn.executemany(
                "UPDATE sessions SET ended_at = ? WHERE session_id = ?",
                [(_format_ts(ts), sid) for sid, ts in self._last_ts.items()],
            )
        if self._alerts:
            conn.executemany(
                "INSERT INTO alerts"
                " (session_id, trigger_message_id, rule_name, severity, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                self._alerts,
            )


def process_stream(
    conn: sqlite3.Connection,
    rules: list[StreamingRule] | None = None,
    gap: timedelta = DEFAULT_GAP,
) -> Stats:
    rules = rules if rules is not None else ALL_RULES
    stats = Stats()

    rows: list[MessageRow] = conn.execute(
        "SELECT * FROM messages WHERE session_id IS NULL"
        " ORDER BY ts, message_id"
    ).fetchall()
    if not rows:
        return stats

    sessionizer = _Sessionizer(conn, gap)
    runner = _RuleRunner(rules)
    writer = _PassWriter()

    with transaction(conn):
        for row in rows:
            if row["enb_ue_s1ap_id"] is None:
                stats.messages_skipped_no_enb_id += 1
                continue

            ts = _parse_ts(row["ts"])
            event = sessionizer.step(row, ts)
            if event.ambiguous:
                stats.messages_skipped_ambiguous_cell += 1
                continue

            if event.closed_id is not None:
                writer.add_alerts(event.closed_id, runner.on_close(event.closed_id))
            if event.opened:
                runner.on_open(event.session_id)
                stats.sessions_created += 1

            writer.add_alerts(event.session_id, runner.on_message(event.session_id, row))
            writer.assign(event.session_id, row["message_id"], ts)
            stats.messages_assigned += 1

        for closed_id in sessionizer.drain():
            writer.add_alerts(closed_id, runner.on_close(closed_id))

        writer.flush(conn)
        stats.alerts_inserted = writer.alert_count

    return stats
