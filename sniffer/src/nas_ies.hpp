#pragma once

#include "framing.hpp"
#include "types.hpp"

#include <optional>

namespace sniffer {

std::optional<EpsMobileIdentity> parse_eps_mobile_identity(ByteSpan ie) noexcept;
std::optional<std::uint8_t> parse_emm_cause(ByteSpan ie) noexcept;

struct NasSecurityAlgorithms {
    std::uint8_t selected_eea;
    std::uint8_t selected_eia;
};
std::optional<NasSecurityAlgorithms> parse_nas_security_algorithms(ByteSpan ie) noexcept;

struct UeNetworkCapability {
    std::uint8_t eea_caps;
    std::uint8_t eia_caps;
};
std::optional<UeNetworkCapability> parse_ue_network_capability(ByteSpan ie) noexcept;

}  // namespace sniffer
