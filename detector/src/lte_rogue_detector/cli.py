"""Command-line entrypoint for the detector.

Usage:
    lte-rogue-detector run <db>          # stream all unassigned messages
    lte-rogue-detector alerts <db>       # print all alerts
"""
import argparse
import sys

from .db import connect
from .engine import process_stream


def _cmd_run(args: argparse.Namespace) -> int:
    conn = connect(args.db)
    s = process_stream(conn)
    print(
        f"stream: {s.sessions_created} session(s), "
        f"{s.messages_assigned} message(s) assigned, "
        f"{s.alerts_inserted} alert(s)"
    )
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

    sp_run = sub.add_parser("run")
    sp_run.add_argument("db", help="path to SQLite database")

    sp_alerts = sub.add_parser("alerts")
    sp_alerts.add_argument("db", help="path to SQLite database")

    args = p.parse_args(argv)
    match args.cmd:
        case "run":
            return _cmd_run(args)
        case "alerts":
            return _print_alerts(args.db)


if __name__ == "__main__":
    sys.exit(main())
