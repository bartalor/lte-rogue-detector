"""Rule + engine behaviour."""
from .conftest import insert_message
from lte_rogue_detector.engine import process_stream
from lte_rogue_detector.nas_types import NasType


def test_imsi_cleartext_attach_fires(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    stats = process_stream(db)
    assert stats.alerts_inserted == 1
    a = db.execute("SELECT rule_name, severity FROM alerts").fetchone()
    assert a["rule_name"] == "imsi_cleartext_attach"
    assert a["severity"] == 5


def test_imsi_cleartext_quiet_when_guti_used(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type=NasType.AttachRequest, identity_type="GUTI",
                   enb_ue_s1ap_id=1)
    stats = process_stream(db)
    assert stats.alerts_inserted == 0


def test_alert_links_to_trigger_message(db):
    m1 = insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                       nas_msg_type=NasType.AttachRequest, identity_type="IMSI",
                       enb_ue_s1ap_id=1)
    process_stream(db)
    a = db.execute(
        "SELECT trigger_message_id FROM alerts"
        " WHERE rule_name = 'imsi_cleartext_attach'"
    ).fetchone()
    assert a["trigger_message_id"] == m1


def _attach(db, *, ts: str, enb_id: int = 1, identity: str = "GUTI") -> int:
    return insert_message(db, ts=ts, direction="UL",
                          nas_msg_type=NasType.AttachRequest,
                          identity_type=identity, enb_ue_s1ap_id=enb_id)


def _aka_alerts(db):
    return db.execute(
        "SELECT trigger_message_id, severity, detail FROM alerts"
        " WHERE rule_name = 'aka_skipped_or_failed'"
    ).fetchall()


def test_aka_skipped_fires_when_smc_without_auth(db):
    _attach(db, ts="2026-05-12T10:00:00.000000Z")
    smc = insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="DL",
                         nas_msg_type=NasType.SecurityModeCommand, enb_ue_s1ap_id=1)
    process_stream(db)
    rows = _aka_alerts(db)
    assert len(rows) == 1
    assert rows[0]["severity"] == 8
    assert rows[0]["trigger_message_id"] == smc


def test_aka_skipped_fires_when_attach_accept_without_auth(db):
    _attach(db, ts="2026-05-12T10:00:00.000000Z")
    aa = insert_message(db, ts="2026-05-12T10:00:00.200000Z", direction="DL",
                        nas_msg_type=NasType.AttachAccept, enb_ue_s1ap_id=1)
    process_stream(db)
    rows = _aka_alerts(db)
    assert len(rows) == 1 and rows[0]["trigger_message_id"] == aa


def test_aka_failure_then_continued_fires(db):
    _attach(db, ts="2026-05-12T10:00:00.000000Z")
    insert_message(db, ts="2026-05-12T10:00:00.050000Z", direction="DL",
                   nas_msg_type=NasType.AuthenticationRequest, enb_ue_s1ap_id=1)
    fail = insert_message(db, ts="2026-05-12T10:00:00.080000Z", direction="UL",
                          nas_msg_type="AuthenticationFailure",
                          enb_ue_s1ap_id=1, emm_cause=20)
    insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="DL",
                   nas_msg_type=NasType.SecurityModeCommand, enb_ue_s1ap_id=1)
    process_stream(db)
    rows = _aka_alerts(db)
    assert len(rows) == 1
    assert rows[0]["trigger_message_id"] == fail
    assert "cause 20" in rows[0]["detail"]


def test_aka_request_without_response_fires(db):
    _attach(db, ts="2026-05-12T10:00:00.000000Z")
    insert_message(db, ts="2026-05-12T10:00:00.050000Z", direction="DL",
                   nas_msg_type=NasType.AuthenticationRequest, enb_ue_s1ap_id=1)
    smc = insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="DL",
                         nas_msg_type=NasType.SecurityModeCommand, enb_ue_s1ap_id=1)
    process_stream(db)
    rows = _aka_alerts(db)
    assert len(rows) == 1 and rows[0]["trigger_message_id"] == smc


def test_aka_completed_is_quiet(db):
    _attach(db, ts="2026-05-12T10:00:00.000000Z")
    insert_message(db, ts="2026-05-12T10:00:00.050000Z", direction="DL",
                   nas_msg_type=NasType.AuthenticationRequest, enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:00.080000Z", direction="UL",
                   nas_msg_type=NasType.AuthenticationResponse, enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="DL",
                   nas_msg_type=NasType.SecurityModeCommand, enb_ue_s1ap_id=1)
    process_stream(db)
    assert _aka_alerts(db) == []


def test_aka_rule_ignores_tau_only_session(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="TrackingAreaUpdateRequest", enb_ue_s1ap_id=1)
    insert_message(db, ts="2026-05-12T10:00:00.100000Z", direction="DL",
                   nas_msg_type=NasType.SecurityModeCommand, enb_ue_s1ap_id=1)
    process_stream(db)
    assert _aka_alerts(db) == []
