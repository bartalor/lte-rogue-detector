"""Sessionizer behaviour (driven through the streaming engine)."""
from .conftest import insert_message
from lte_rogue_detector.engine import process_stream
from lte_rogue_detector.nas_types import NasType


def _stream(db):
    # Sessionize-only: stream with no rules so we exercise the lifecycle
    # bookkeeping without firing alerts.
    return process_stream(db, rules=[])


def test_single_session(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:00.500000Z", direction="DL",
                   nas_msg_type=NasType.AuthenticationRequest, enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:01.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachComplete, enb_ue_s1ap_id=1)

    stats = _stream(db)
    assert stats.sessions_created == 1
    assert stats.messages_assigned == 3

    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids == [1, 1, 1]


def test_detach_closes_session(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:01.000000Z", direction="UL",
                   nas_msg_type="DetachRequest", enb_ue_s1ap_id=1)
    # Same eNB ID immediately after detach: must start a new session even
    # though we're within the gap.
    insert_message(db, ts="2026-05-12T10:00:02.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)

    _stream(db)
    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids[0] == sids[1] != sids[2]


def test_gap_starts_new_session(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    # 31s gap > default 30s threshold.
    insert_message(db, ts="2026-05-12T10:00:31.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)

    _stream(db)
    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids[0] != sids[1]


def test_different_enb_ids_are_separate(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=2)

    _stream(db)
    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids[0] != sids[1]


def test_idempotent_skips_assigned(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    first = _stream(db)
    second = _stream(db)
    assert first.messages_assigned == 1
    assert second.messages_assigned == 0
    assert second.sessions_created == 0


def test_skips_rows_without_enb_id(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=None)

    stats = _stream(db)
    assert stats.sessions_created == 0
    assert stats.messages_skipped_no_enb_id == 1


def test_same_enb_id_on_different_cells_separates_sessions(db):
    # Cell A (legit) and cell B (rogue) both happen to allocate
    # enb_ue_s1ap_id = 42. Without cell-aware keying the sessionizer would
    # collapse them into one session and mask the rogue's missing AKA.
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=42, plmn="00101", cell_id=0x100)
    insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=42, plmn="00102", cell_id=0x200)

    _stream(db)
    sids = [r["session_id"] for r in
            db.execute("SELECT session_id FROM messages ORDER BY message_id")]
    assert sids[0] != sids[1]
    rows = db.execute(
        "SELECT plmn, cell_id FROM sessions ORDER BY session_id"
    ).fetchall()
    assert (rows[0]["plmn"], rows[0]["cell_id"]) == ("00101", 0x100)
    assert (rows[1]["plmn"], rows[1]["cell_id"]) == ("00102", 0x200)


def test_downlink_resolves_to_correct_cell_via_mme_id(db):
    # Two cells both have enb_ue_s1ap_id=1 open. A downlink arrives with
    # mme_ue_s1ap_id=222 matching only the second cell's session.
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1, plmn="00101", cell_id=0x100)
    insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1, plmn="00102", cell_id=0x200)
    # Sniffer can't carry MME-UE-S1AP-ID on InitialUEMessage; it's first
    # set by the MME on the downlink response. Latch it on the matching
    # uplink by inserting a later UplinkNASTransport-style row.
    insert_message(db, ts="2026-05-12T10:00:00.200000Z", direction="UL",
                   nas_msg_type=NasType.AuthenticationResponse,
                   enb_ue_s1ap_id=1, mme_ue_s1ap_id=222,
                   plmn="00102", cell_id=0x200)
    insert_message(db, ts="2026-05-12T10:00:00.300000Z", direction="DL",
                   nas_msg_type=NasType.SecurityModeCommand,
                   enb_ue_s1ap_id=1, mme_ue_s1ap_id=222)

    _stream(db)
    rows = db.execute(
        "SELECT m.message_id, m.session_id, s.cell_id"
        " FROM messages m JOIN sessions s ON s.session_id = m.session_id"
        " ORDER BY m.message_id"
    ).fetchall()
    # The DL row (last) must land on the cell=0x200 session.
    assert rows[-1]["cell_id"] == 0x200


def test_ended_at_set_to_last_message_ts(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:05.000000Z", direction="UL",
                   nas_msg_type="DetachRequest", enb_ue_s1ap_id=1)
    _stream(db)
    row = db.execute("SELECT started_at, ended_at FROM sessions").fetchone()
    assert row["started_at"] == "2026-05-12T10:00:00.000000Z"
    assert row["ended_at"] == "2026-05-12T10:00:05.000000Z"
