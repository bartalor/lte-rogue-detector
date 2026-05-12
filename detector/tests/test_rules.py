"""Rule + engine behaviour."""
from .conftest import insert_message
from lte_rogue_detector.engine import run_rules
from lte_rogue_detector.sessionize import sessionize


def test_imsi_cleartext_attach_fires(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="IMSI",
                   enb_ue_s1ap_id=1)
    sessionize(db)
    stats = run_rules(db)
    assert stats.alerts_inserted == 1
    a = db.execute("SELECT rule_name, severity FROM alerts").fetchone()
    assert a["rule_name"] == "imsi_cleartext_attach"
    assert a["severity"] == 5


def test_imsi_cleartext_quiet_when_guti_used(db):
    insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                   nas_msg_type="AttachRequest", identity_type="GUTI",
                   enb_ue_s1ap_id=1)
    sessionize(db)
    stats = run_rules(db)
    assert stats.alerts_inserted == 0


def test_alert_links_to_trigger_message(db):
    m1 = insert_message(db, ts="2026-05-12T10:00:00.000000Z", direction="UL",
                       nas_msg_type="AttachRequest", identity_type="IMSI",
                       enb_ue_s1ap_id=1)
    sessionize(db)
    run_rules(db)
    a = db.execute("SELECT trigger_message_id FROM alerts").fetchone()
    assert a["trigger_message_id"] == m1
