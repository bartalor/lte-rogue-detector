"""Rule: AttachRequest sent IMSI in cleartext.

The first message of an LTE attach (AttachRequest, carried in S1AP
InitialUEMessage) includes an EPS Mobile Identity IE that identifies the
UE. A UE that has previously attached to a real network holds a GUTI
(globally unique temporary identity) and is expected to use it here; a
genuine network only falls back to asking for the IMSI when it doesn't
recognise the GUTI (IdentityRequest → IdentityResponse).

A rogue eNB has no GUTI database, so its quickest way to learn the IMSI
is to force the UE to disclose it on the very first message - either by
rejecting prior attaches with causes that wipe the UE's GUTI, or simply
by claiming an unfamiliar PLMN/TAI so the UE selects "IMSI" as the
identity to send. Either way, the wire signature is the same: an
AttachRequest whose EPS Mobile Identity is IMSI.

This rule flags exactly that. We can't tell from a single session whether
the UE *had* a GUTI it could have used, so severity is medium (5). A
follow-up rule that correlates across sessions can promote it to high.
"""
from typing import Iterable

from .base import Alert, Session


class ImsiCleartextWithGutiRule:
    name = "imsi_cleartext_attach"
    severity = 5

    def evaluate(self, session: Session) -> Iterable[Alert]:
        for m in session.messages:
            if m["nas_msg_type"] != "AttachRequest":
                continue
            if m["identity_type"] == "IMSI":
                yield Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    trigger_message_id=m["message_id"],
                    detail=(
                        "AttachRequest carries IMSI in cleartext; UE did "
                        "not use a GUTI as expected after a prior attach"
                    ),
                )
            # AttachRequest carries one EPS Mobile Identity; first hit is enough.
            return
