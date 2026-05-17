"""Canonical NAS message-type names.

Mirrors the C++ enum in sniffer/src/types.hpp / db.cpp::to_string. The
sniffer writes these strings into SQLite; everything Python-side that
compares against `messages.nas_msg_type` imports from here.
"""

from __future__ import annotations

from enum import StrEnum


class NasType(StrEnum):
    AttachRequest = "AttachRequest"
    AttachAccept = "AttachAccept"
    AttachComplete = "AttachComplete"
    AttachReject = "AttachReject"
    IdentityRequest = "IdentityRequest"
    IdentityResponse = "IdentityResponse"
    AuthenticationRequest = "AuthenticationRequest"
    AuthenticationResponse = "AuthenticationResponse"
    SecurityModeCommand = "SecurityModeCommand"
    SecurityModeComplete = "SecurityModeComplete"
