"""Rule: EPS-AKA was skipped or did not complete before SecurityModeCommand.

A legitimate MME, before activating NAS security on a fresh context, runs
EPS-AKA: it sends AuthenticationRequest (RAND + AUTN), the UE verifies
AUTN with its USIM and replies with AuthenticationResponse (RES). Only
then does SecurityModeCommand select algorithms and start integrity
protection. AttachAccept comes later still.

A rogue eNB has no access to the subscriber's K, so it cannot forge a
valid AUTN. Two failure modes betray it:

  * Skipped: it jumps straight from AttachRequest to SecurityModeCommand
    (or AttachAccept) with no AuthenticationRequest at all - hoping the
    UE will accept null algorithms and never notice. This is the
    canonical signature.
  * Failed: it gambles on AuthenticationRequest with a guessed/replayed
    AUTN; the UE's USIM rejects it and emits AuthenticationFailure
    (EMM cause 20 'MAC failure' or 21 'synch failure'), or simply never
    responds before the procedure moves on.

Either way, NAS security got activated (or attempted) without a
completed mutual-authentication exchange. That should not happen on a
real network.

Severity 8: skipping mutual auth is a much stronger signal than IMSI
disclosure (rule 1, severity 5), which has benign explanations.
"""
from typing import Iterable

from .base import Alert, Session


# NAS messages that mark "the procedure moved past authentication".
# If we see one of these in a session without a completed AKA exchange
# preceding it, AKA was effectively skipped.
_POST_AUTH = {"SecurityModeCommand", "AttachAccept"}


class AkaSkippedOrFailedRule:
    name = "aka_skipped_or_failed"
    severity = 8

    def evaluate(self, session: Session) -> Iterable[Alert]:
        # We only judge sessions that actually started an attach. TAU-only
        # sessions can legitimately reuse an existing security context and
        # skip AKA; flagging them would be a false positive.
        if not any(m["nas_msg_type"] == "AttachRequest" for m in session.messages):
            return

        auth_req: dict | None = None
        auth_completed = False
        auth_failure_msg: dict | None = None

        for m in session.messages:
            t = m["nas_msg_type"]
            if t == "AuthenticationRequest":
                auth_req = m
                auth_completed = False
                auth_failure_msg = None
            elif t == "AuthenticationResponse" and auth_req is not None:
                auth_completed = True
            elif t == "AuthenticationFailure" and auth_req is not None:
                auth_failure_msg = m
            elif t in _POST_AUTH and not auth_completed:
                if auth_req is None:
                    yield Alert(
                        rule_name=self.name,
                        severity=self.severity,
                        trigger_message_id=m["message_id"],
                        detail=(
                            f"{t} reached without any AuthenticationRequest;"
                            " EPS-AKA was skipped entirely"
                        ),
                    )
                elif auth_failure_msg is not None:
                    cause = auth_failure_msg["emm_cause"]
                    yield Alert(
                        rule_name=self.name,
                        severity=self.severity,
                        trigger_message_id=auth_failure_msg["message_id"],
                        detail=(
                            f"AuthenticationFailure (EMM cause {cause}) but"
                            f" procedure continued to {t}; AKA did not complete"
                        ),
                    )
                else:
                    yield Alert(
                        rule_name=self.name,
                        severity=self.severity,
                        trigger_message_id=m["message_id"],
                        detail=(
                            f"{t} reached without AuthenticationResponse;"
                            " AKA challenge was issued but never answered"
                        ),
                    )
                return
