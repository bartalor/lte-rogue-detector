#pragma once

#include "framing.hpp"
#include "types.hpp"

#include <optional>

namespace sniffer {

// Decode a NAS-EPS PDU. Returns std::nullopt for malformed input or for
// message types this project does not care about.
std::optional<DecodedNasMessage> decode_nas(ByteSpan pdu) noexcept;

}  // namespace sniffer
