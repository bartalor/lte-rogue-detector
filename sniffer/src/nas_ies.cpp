#include "nas_ies.hpp"

namespace sniffer {

std::optional<EpsMobileIdentity> parse_eps_mobile_identity(ByteSpan /*ie*/) noexcept {
    return std::nullopt;
}

std::optional<std::uint8_t> parse_emm_cause(ByteSpan /*ie*/) noexcept {
    return std::nullopt;
}

std::optional<NasSecurityAlgorithms> parse_nas_security_algorithms(ByteSpan /*ie*/) noexcept {
    return std::nullopt;
}

std::optional<UeNetworkCapability> parse_ue_network_capability(ByteSpan /*ie*/) noexcept {
    return std::nullopt;
}

}  // namespace sniffer
