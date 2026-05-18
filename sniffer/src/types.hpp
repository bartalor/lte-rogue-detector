#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sniffer {

enum class Direction : std::uint8_t {
    Uplink,
    Downlink,
    Unknown,
};

enum class NasMessageType : std::uint8_t {
    AttachRequest = 0x41,
    AttachAccept = 0x42,
    AttachComplete = 0x43,
    AttachReject = 0x44,
    DetachRequest = 0x45,
    TauRequest = 0x48,
    TauAccept = 0x49,
    TauReject = 0x4b,
    IdentityRequest = 0x55,
    IdentityResponse = 0x56,
    AuthenticationRequest = 0x52,
    AuthenticationResponse = 0x53,
    AuthenticationReject = 0x54,
    AuthenticationFailure = 0x5c,
    SecurityModeCommand = 0x5d,
    SecurityModeComplete = 0x5e,
    SecurityModeReject = 0x5f,
    Unknown = 0x00,
};

struct EpsMobileIdentity {
    enum class Kind { Imsi, Guti, Imei, Other } kind;
    std::string value;
};

struct DecodedNasMessage {
    NasMessageType type{NasMessageType::Unknown};
    std::uint8_t security_header_type{0};
    std::optional<EpsMobileIdentity> mobile_identity;
    std::optional<std::uint8_t> identity_request_type;
    std::optional<std::uint8_t> emm_cause;
    std::optional<std::uint8_t> selected_eea;
    std::optional<std::uint8_t> selected_eia;
    std::optional<std::uint8_t> ue_eea_caps;
    std::optional<std::uint8_t> ue_eia_caps;
    std::vector<std::uint8_t> raw;
};

struct ExtractedFields {
    Direction direction{Direction::Unknown};
    std::optional<std::uint32_t> enb_ue_s1ap_id;
    std::optional<std::uint32_t> mme_ue_s1ap_id;
    std::optional<std::uint32_t> s1ap_procedure_code;
    std::optional<std::uint32_t> cell_id;          // 28-bit Cell Identity
    std::optional<std::array<std::uint8_t, 3>> plmn_bcd;  // 3 BCD bytes
    std::optional<std::uint32_t> tac;
    DecodedNasMessage nas;
    std::uint64_t ts_us{0};
};

}  // namespace sniffer
