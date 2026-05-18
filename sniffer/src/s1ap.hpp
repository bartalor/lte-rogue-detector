#pragma once

#include "framing.hpp"
#include "types.hpp"

#include <array>
#include <optional>

namespace sniffer {

// Peel an S1AP-PDU just enough to find the NAS-PDU IE and the per-message
// identifiers we care about (procedure code, eNB-UE-S1AP-ID, MME-UE-S1AP-ID).
// Returns std::nullopt if the PDU is not one of InitialUEMessage /
// DownlinkNASTransport / UplinkNASTransport, or has no NAS-PDU IE.
struct S1apPeel {
    std::uint32_t procedure_code{0};
    std::optional<std::uint32_t> enb_ue_s1ap_id;
    std::optional<std::uint32_t> mme_ue_s1ap_id;
    // EUTRAN-CGI: PLMN as the 3 BCD-encoded bytes on the wire (MCC/MNC-MNC
    // packed per TS 24.008 §10.5.1.3) and the 28-bit Cell Identity. Present
    // on InitialUEMessage and UplinkNASTransport; absent on
    // DownlinkNASTransport.
    std::optional<std::array<std::uint8_t, 3>> plmn;
    std::optional<std::uint32_t> cell_id;
    ByteSpan nas_pdu{};
};

std::optional<S1apPeel> peel_s1ap(ByteSpan s1ap) noexcept;

}  // namespace sniffer
