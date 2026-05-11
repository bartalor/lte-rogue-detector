#include "framing.hpp"

namespace sniffer {

std::optional<ByteSpan> sll_to_s1ap_payload(const std::uint8_t* /*pkt*/, std::size_t /*len*/) noexcept {
    return std::nullopt;
}

}  // namespace sniffer
