#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>

namespace sniffer {

struct ByteSpan {
    const std::uint8_t* data{nullptr};
    std::size_t len{0};
};

enum class LinkPayloadKind {
    RawNas,    // The whole packet is a NAS-EPS PDU (DLT_USER_1, linktype 148).
    S1apPdu,   // Payload of an SCTP DATA chunk with PPID 18 (S1AP).
};

struct LinkPayload {
    LinkPayloadKind kind;
    ByteSpan span;
};

// Decode a pcap record down to the protocol payload above SCTP (or pass through
// raw NAS for linktype 148). Returns multiple payloads when a single SCTP packet
// carries several DATA chunks. Empty vector means nothing relevant in the packet.
std::vector<LinkPayload> link_payloads(
    int linktype, const std::uint8_t* pkt, std::size_t len) noexcept;

// Peel SLL -> IPv4 -> SCTP and return every S1AP-bearing DATA chunk payload
// (PPID 18). Exposed for direct testing.
std::vector<ByteSpan> sll_to_s1ap_payloads(const std::uint8_t* pkt, std::size_t len) noexcept;

}  // namespace sniffer
