#include "nas.hpp"

namespace sniffer {

std::optional<DecodedNasMessage> decode_nas(ByteSpan /*pdu*/) noexcept {
    return std::nullopt;
}

}  // namespace sniffer
