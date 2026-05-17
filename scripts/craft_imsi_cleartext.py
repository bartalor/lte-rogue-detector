#!/usr/bin/env python3
"""Craft a pcap for the IMSI-in-cleartext-during-attach rogue scenario.

Models a rogue MME that, on receiving an Attach Request whose mobile identity
is a valid GUTI (S-TMSI), responds with NAS Identity Request (IMSI) rather
than running AKA against the GUTI's mapped IMSI. A legitimate MME with a
known GUTI never needs to ask the UE for its IMSI in cleartext.

Three NAS messages, wrapped in three S1AP PDUs, framed over SCTP/IP/Ethernet:

  1. UE -> MME  S1AP InitialUEMessage     NAS AttachRequest (id=GUTI)
  2. MME -> UE  S1AP DownlinkNASTransport NAS IdentityRequest (IMSI)
  3. UE -> MME  S1AP UplinkNASTransport   NAS IdentityResponse (IMSI)

All wire-format encoding goes through pycrate:
  - NAS messages: pycrate_mobile.TS24301_EMM
  - Mobile-identity TLVs (GUTI, IMSI): EPSID / ID from TS24301_IE / TS24008_IE
  - PLMN BCD: TS24008_IE.PLMN
  - S1AP PDUs: pycrate_asn1dir.S1AP (ASN.1 APER)
SCTP/IP framing via scapy.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from pycrate_asn1dir import S1AP
from pycrate_mobile.TS24008_IE import ID, PLMN
from pycrate_mobile.TS24301_EMM import (
    EMMAttachRequest,
    EMMIdentityRequest,
    EMMIdentityResponse,
)
from pycrate_mobile.TS24301_IE import EPSID, IDTYPE_GUTI, IDTYPE_IMSI
from scapy.all import Ether, IP, SCTP, SCTPChunkData, wrpcap

from lte_rogue_detector.nas_types import NasType


ENB_IP = "127.0.0.1"
MME_IP = "127.0.0.2"
SCTP_SPORT = 36412
SCTP_DPORT = 36412
S1AP_PPID = 18  # IANA-assigned SCTP payload protocol id for S1AP

PLMN_DIGITS = "00101"  # MCC=001, MNC=01
TAC = 1
CELL_ID = 0x19B
ENB_UE_S1AP_ID = 1
MME_UE_S1AP_ID = 1

# GUTI components (TS 24.301 §9.9.3.12). M-TMSI is the per-UE temporary id
# allocated by the MME; the rogue MME ignores it and demands the IMSI.
GUTI_MMEGI = 0x0001
GUTI_MMEC = 0x01
GUTI_MTMSI = 0xC0DECAFE

IMSI = "001010123456789"


def _plmn_bytes() -> bytes:
    p = PLMN()
    p.encode(PLMN_DIGITS)
    return p.to_bytes()


def _guti_eps_id_bytes() -> bytes:
    e = EPSID()
    e.encode(IDTYPE_GUTI, (PLMN_DIGITS, GUTI_MMEGI, GUTI_MMEC, GUTI_MTMSI))
    return e.to_bytes()


def _imsi_mobile_id_bytes() -> bytes:
    i = ID()
    i.encode(IDTYPE_IMSI, IMSI)
    return i.to_bytes()


# ---------- NAS messages ----------
#
# All three NAS messages are pure field-assignment: pick the right pycrate
# class, set values on V fields, serialise. No per-message logic, so one
# dispatcher with the message class registry is enough. The per-message
# TS 24.301 references live at the call sites in craft() where a reader
# wants them.

_NAS_CLASSES = {
    NasType.AttachRequest:    EMMAttachRequest,
    NasType.IdentityRequest:  EMMIdentityRequest,
    NasType.IdentityResponse: EMMIdentityResponse,
}


def build_nas(msg_type: NasType, **fields) -> bytes:
    """Build a NAS message of the given type with the given IE values.

    `fields` keys are pycrate IE names (e.g. NAS_KSI, EPSID, IDType, ID);
    values are passed to that IE's V field. KeyError from pycrate if a
    field name doesn't exist on the chosen message type.
    """
    msg = _NAS_CLASSES[msg_type]()
    for name, val in fields.items():
        msg[name]["V"].set_val(val)
    return msg.to_bytes()


# ---------- S1AP PDUs ----------
#
# All three S1AP PDUs we emit share the same shape: an initiatingMessage
# carrying a NAS-PDU plus per-procedure IEs. Each procedure's IE list is
# specified inline at the call site (a list of pycrate-shaped IE dicts);
# the shared encoder handles the procedure-code/criticality/PDU-choice
# wrapping that is identical across all three.

def _encode_s1ap_initiating(proc_code: int, proc_name: str, ies: list) -> bytes:
    pdu = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    pdu.set_val(("initiatingMessage", {
        "procedureCode": proc_code,
        "criticality": "ignore",
        "value": (proc_name, {"protocolIEs": ies}),
    }))
    return pdu.to_aper()


def _ie(ie_id: int, criticality: str, name: str, value):
    return {"id": ie_id, "criticality": criticality, "value": (name, value)}


def _initial_ue_message(nas_pdu: bytes) -> bytes:
    """S1AP InitialUEMessage, TS 36.413 §9.1.7.1."""
    return _encode_s1ap_initiating(12, "InitialUEMessage", [
        _ie(8, "reject", "ENB-UE-S1AP-ID", ENB_UE_S1AP_ID),
        _ie(26, "reject", "NAS-PDU", nas_pdu),
        _ie(67, "reject", "TAI", {
            "pLMNidentity": _plmn_bytes(),
            "tAC": TAC.to_bytes(2, "big"),
        }),
        _ie(100, "ignore", "EUTRAN-CGI", {
            "pLMNidentity": _plmn_bytes(),
            "cell-ID": (CELL_ID, 28),
        }),
        _ie(134, "ignore", "RRC-Establishment-Cause", "mo-Signalling"),
    ])


def _dl_nas_transport(nas_pdu: bytes) -> bytes:
    """S1AP DownlinkNASTransport, TS 36.413 §9.1.7.2."""
    return _encode_s1ap_initiating(11, "DownlinkNASTransport", [
        _ie(0, "reject", "MME-UE-S1AP-ID", MME_UE_S1AP_ID),
        _ie(8, "reject", "ENB-UE-S1AP-ID", ENB_UE_S1AP_ID),
        _ie(26, "reject", "NAS-PDU", nas_pdu),
    ])


def _ul_nas_transport(nas_pdu: bytes) -> bytes:
    """S1AP UplinkNASTransport, TS 36.413 §9.1.7.3."""
    return _encode_s1ap_initiating(13, "UplinkNASTransport", [
        _ie(0, "reject", "MME-UE-S1AP-ID", MME_UE_S1AP_ID),
        _ie(8, "reject", "ENB-UE-S1AP-ID", ENB_UE_S1AP_ID),
        _ie(26, "reject", "NAS-PDU", nas_pdu),
        _ie(100, "ignore", "EUTRAN-CGI", {
            "pLMNidentity": _plmn_bytes(),
            "cell-ID": (CELL_ID, 28),
        }),
        _ie(67, "reject", "TAI", {
            "pLMNidentity": _plmn_bytes(),
            "tAC": TAC.to_bytes(2, "big"),
        }),
    ])


# ---------- Framing ----------

def _frame(src_ip: str, dst_ip: str, sport: int, dport: int, s1ap_bytes: bytes,
           tsn: int, stream_seq: int):
    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    ip = IP(src=src_ip, dst=dst_ip)
    sctp = SCTP(sport=sport, dport=dport)
    chunk = SCTPChunkData(
        tsn=tsn,
        stream_id=1,
        stream_seq=stream_seq,
        proto_id=S1AP_PPID,
        data=s1ap_bytes,
    )
    return eth / ip / sctp / chunk


def craft(out_dir: Path) -> Path:
    # NAS Attach Request, mobile identity = GUTI (TS 24.301 §8.2.4).
    attach_nas = build_nas(
        NasType.AttachRequest,
        NAS_KSI=7,
        EPSAttachType=1,                # 1 = EPS attach
        EPSID=_guti_eps_id_bytes(),
        UENetCap=b"\xe0\xe0",           # EEA0/1/2 + EIA0/1/2 advertised
        ESMContainer=b"\x00\x00\x00",   # placeholder; detector doesn't inspect
    )
    # NAS Identity Request, ID type = IMSI (TS 24.301 §8.2.18). The rogue
    # smoking gun: a legitimate MME with a known GUTI never asks for IMSI.
    idreq_nas = build_nas(NasType.IdentityRequest, IDType=1)
    # NAS Identity Response, IMSI in cleartext (TS 24.301 §8.2.19).
    idresp_nas = build_nas(NasType.IdentityResponse, ID=_imsi_mobile_id_bytes())

    packets = [
        _frame(ENB_IP, MME_IP, SCTP_SPORT, SCTP_DPORT, _initial_ue_message(attach_nas), tsn=1, stream_seq=0),
        _frame(MME_IP, ENB_IP, SCTP_DPORT, SCTP_SPORT, _dl_nas_transport(idreq_nas),    tsn=1, stream_seq=0),
        _frame(ENB_IP, MME_IP, SCTP_SPORT, SCTP_DPORT, _ul_nas_transport(idresp_nas),   tsn=2, stream_seq=1),
    ]
    t0 = dt.datetime.now().timestamp()
    for i, pkt in enumerate(packets):
        pkt.time = t0 + 0.020 * i

    out_dir.mkdir(parents=True, exist_ok=True)
    pcap = out_dir / "rogue_imsi_cleartext.pcap"
    meta = out_dir / "rogue_imsi_cleartext.json"
    wrpcap(str(pcap), packets)

    meta.write_text(json.dumps({
        "name": "rogue_imsi_cleartext",
        "scenario": "imsi_requested_in_cleartext_with_valid_guti",
        "plmn": {"mcc": PLMN_DIGITS[:3], "mnc": PLMN_DIGITS[3:]},
        "tac": TAC,
        "imsi": IMSI,
        "guti": {"mmegi": GUTI_MMEGI, "mmec": GUTI_MMEC, "m_tmsi": f"0x{GUTI_MTMSI:08x}"},
        "messages": ["AttachRequest(GUTI)", "IdentityRequest(IMSI)", "IdentityResponse(IMSI)"],
        "crafted_with": "pycrate (S1AP+NAS+IEs) + scapy (SCTP/IP)",
    }, indent=2))
    return pcap


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out-dir", type=Path,
                   default=Path(__file__).resolve().parent.parent / "sample_pcaps")
    args = p.parse_args()
    pcap = craft(args.out_dir)
    print(f"wrote {pcap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
