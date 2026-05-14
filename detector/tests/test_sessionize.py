"""Sessionizer behaviour (driven through the streaming engine)."""
from .conftest import insert_message
from lte_rogue_detector.engine import process_stream


def _stream(db):
    # Sessionize-only: stream with no rules so we exercise the lifecycle
    # bookkeeping without firing alerts.
    return process_stream(db, rules=[])


def test_single_session(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:00.500000Z", direction="DL",
                   nas_msg_type="AuthenticationRequest", enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:01.000000Z", direction="UL",
                   nas_msg_type="AttachComplete", enb_ue_s1ap_id=1)

    stats = _stream(db)
    assert stats.sessions_created == 1
    assert stats.messages_assigned == 3

    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids == [1, 1, 1]


def test_detach_closes_session(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:01.000000Z", direction="UL",
                   nas_msg_type="DetachRequest", enb_ue_s1ap_id=1)
    # Same eNB ID immediately after detach: must start a new session even
    # though we're within the gap.
    insert_message(db, ts="2026-05-12T10:00:02.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)

    _stream(db)
    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids[0] == sids[1] != sids[2]


def test_gap_starts_new_session(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    # 31s gap > default 30s threshold.
    insert_message(db, ts="2026-05-12T10:00:31.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)

    _stream(db)
    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids[0] != sids[1]


def test_different_enb_ids_are_separate(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=2)

    _stream(db)
    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids[0] != sids[1]


def test_idempotent_skips_assigned(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    first = _stream(db)
    second = _stream(db)
    assert first.messages_assigned == 1
    assert second.messages_assigned == 0
    assert second.sessions_created == 0


def test_skips_rows_without_enb_id(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=None)

    stats = _stream(db)
    assert stats.sessions_created == 0
    assert stats.messages_skipped_no_enb_id == 1


def test_ended_at_set_to_last_message_ts(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:05.000000Z", direction="UL",
                   nas_msg_type="DetachRequest", enb_ue_s1ap_id=1)
    _stream(db)
    row = db.execute("SELECT started_at, ended_at FROM sessions").fetchone()
    assert row["started_at"] == "2026-05-12T10:00:00.000000Z"
    assert row["ended_at"] == "2026-05-12T10:00:05.000000Z"
