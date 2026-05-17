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
import sqlite3
from typing import Any, Iterable

from ..nas_types import NasType
from .base import Alert


# NAS messages that mark "the procedure moved past authentication".
# If we see one of these in a session without a completed AKA exchange
# preceding it, AKA was effectively skipped.
_POST_AUTH = {NasType.SecurityModeCommand, NasType.AttachAccept}


class AkaSkippedOrFailedRule:
    name = "aka_skipped_or_failed"
    severity = 8

    def observe(
        self, msg: sqlite3.Row, state: dict[str, Any]
    ) -> Iterable[Alert]:
        if state.get("fired"):
            return

        t = msg["nas_msg_type"]

        if t == NasType.AttachRequest:
            state["attach_seen"] = True
            return

        # Without an AttachRequest we don't judge — TAU-only sessions can
        # legitimately reuse an existing security context and skip AKA.
        if not state.get("attach_seen"):
            return

        if t == NasType.AuthenticationRequest:
            state["auth_req"] = msg
            state["auth_completed"] = False
            state["auth_failure_msg"] = None
            return
        if t == NasType.AuthenticationResponse and state.get("auth_req") is not None:
            state["auth_completed"] = True
            return
        if t == "AuthenticationFailure" and state.get("auth_req") is not None:
            state["auth_failure_msg"] = msg
            return

        if t in _POST_AUTH and not state.get("auth_completed"):
            state["fired"] = True
            auth_req = state.get("auth_req")
            failure = state.get("auth_failure_msg")
            if auth_req is None:
                yield Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    trigger_message_id=msg["message_id"],
                    detail=(
                        f"{t} reached without any AuthenticationRequest;"
                        " EPS-AKA was skipped entirely"
                    ),
                )
            elif failure is not None:
                cause = failure["emm_cause"]
                yield Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    trigger_message_id=failure["message_id"],
                    detail=(
                        f"AuthenticationFailure (EMM cause {cause}) but"
                        f" procedure continued to {t}; AKA did not complete"
                    ),
                )
            else:
                yield Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    trigger_message_id=msg["message_id"],
                    detail=(
                        f"{t} reached without AuthenticationResponse;"
                        " AKA challenge was issued but never answered"
                    ),
                )

    def on_session_close(self, state: dict[str, Any]) -> Iterable[Alert]:
        return ()
