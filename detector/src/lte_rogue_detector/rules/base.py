"""Rule interface shared by all detection rules.

Rules are streaming consumers: the engine feeds them one message at a time
in ts order, scoped to a single session, and tells them when the session
closes. Each rule gets its own per-session `state` dict to carry whatever
it needs across messages — the engine never inspects it.
"""
from dataclasses import dataclass
from typing import Any, Iterable, Protocol, TypedDict


class MessageRow(TypedDict):
    """Columns of a `messages` row as the engine and rules see it."""
    message_id: int
    session_id: int | None
    ts: str
    direction: str
    nas_msg_type: str
    enb_ue_s1ap_id: int | None
    mme_ue_s1ap_id: int | None
    plmn: str | None
    cell_id: int | None
    identity_type: str | None
    eea_selected: int | None
    eia_selected: int | None
    ue_eea_caps: int | None
    ue_eia_caps: int | None
    emm_cause: int | None
    raw_pcap_offset: int | None
    raw_frame_number: int | None


@dataclass(frozen=True)
class Alert:
    rule_name: str
    severity: int
    trigger_message_id: int | None
    detail: str


class StreamingRule(Protocol):
    name: str
    severity: int

    def observe(
        self, msg: MessageRow, state: dict[str, Any]
    ) -> Iterable[Alert]: ...

    def on_session_close(
        self, state: dict[str, Any]
    ) -> Iterable[Alert]: ...
