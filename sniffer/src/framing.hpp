#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

namespace sniffer {

struct ByteSpan {
    const std::uint8_t* data{nullptr};
    std::size_t len{0};
};

// Peel SLL -> IPv4 -> SCTP and return the first SCTP DATA chunk payload that
// carries S1AP (PPID 18). std::nullopt if the packet does not contain one.
std::optional<ByteSpan> sll_to_s1ap_payload(const std::uint8_t* pkt, std::size_t len) noexcept;

}  // namespace sniffer
