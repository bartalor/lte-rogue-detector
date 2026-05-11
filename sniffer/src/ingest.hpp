#pragma once

#include "types.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>

namespace sniffer {

// Take one pcap record (after the per-packet header) plus the pcap's link layer
// type and decode it into zero or more ExtractedFields. A single SCTP packet
// may carry several S1AP DATA chunks, hence vector.
std::vector<ExtractedFields> ingest_packet(
    int linktype,
    const std::uint8_t* data,
    std::size_t len,
    std::uint64_t ts_us) noexcept;

}  // namespace sniffer
