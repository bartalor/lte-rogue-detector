"""Command-line entrypoint for the detector.

Usage:
    lte-rogue-detector sessionize <db>
    lte-rogue-detector run <db>          # sessionize then evaluate rules
    lte-rogue-detector alerts <db>       # print all alerts
"""
from __future__ import annotations

import argparse
import sys

from .db import connect
from .engine import run_rules
from .sessionize import sessionize


def _cmd_sessionize(args: argparse.Namespace) -> int:
    conn = connect(args.db)
    stats = sessionize(conn)
    print(
        f"sessionize: {stats.sessions_created} session(s), "
        f"{stats.messages_assigned} message(s) assigned, "
        f"{stats.messages_skipped_no_enb_id} skipped (no eNB ID)"
    )
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    conn = connect(args.db)
    s = sessionize(conn)
    print(
        f"sessionize: {s.sessions_created} session(s), "
        f"{s.messages_assigned} message(s) assigned"
    )
    e = run_rules(conn)
    print(
        f"rules: {e.sessions_evaluated} session(s) evaluated, "
        f"{e.alerts_inserted} alert(s)"
    )
    return _print_alerts(args.db)


def _cmd_alerts(args: argparse.Namespace) -> int:
    return _print_alerts(args.db)


def _print_alerts(db_path: str) -> int:
    conn = connect(db_path)
    rows = conn.execute(
        """
        SELECT a.alert_id, a.severity, a.rule_name, a.detail,
               s.session_id, s.enb_ue_s1ap_id, s.started_at,
               m.ts AS trigger_ts, m.nas_msg_type AS trigger_type
        FROM alerts a
        JOIN sessions s ON s.session_id = a.session_id
        LEFT JOIN messages m ON m.message_id = a.trigger_message_id
        ORDER BY a.severity DESC, a.alert_id
        """
    ).fetchall()
    if not rows:
        print("no alerts")
        return 0
    for r in rows:
        print(
            f"[sev {r['severity']}] {r['rule_name']}"
            f"  session={r['session_id']}"
            f"  enb_ue_s1ap_id={r['enb_ue_s1ap_id']}"
            f"  trigger={r['trigger_type']}@{r['trigger_ts']}\n"
            f"           {r['detail']}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lte-rogue-detector")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, fn in [
        ("sessionize", _cmd_sessionize),
        ("run", _cmd_run),
        ("alerts", _cmd_alerts),
    ]:
        sp = sub.add_parser(name)
        sp.add_argument("db", help="path to SQLite database")
        sp.set_defaults(func=fn)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
