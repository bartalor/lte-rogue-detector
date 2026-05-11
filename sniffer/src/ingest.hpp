#pragma once

#include "types.hpp"

#include <cstdint>
#include <cstddef>
#include <optional>

namespace sniffer {

// Take one pcap record (after the per-packet header) plus the pcap's link
// layer type and decode it down to an ExtractedFields. Returns nullopt if
// the packet does not yield a NAS message we care about.
std::optional<ExtractedFields> ingest_packet(
    int linktype,
    const std::uint8_t* data,
    std::size_t len,
    std::uint64_t ts_us) noexcept;

}  // namespace sniffer
