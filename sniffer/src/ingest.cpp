#include "ingest.hpp"

namespace sniffer {

std::optional<ExtractedFields> ingest_packet(
    int /*linktype*/,
    const std::uint8_t* /*data*/,
    std::size_t /*len*/,
    std::uint64_t /*ts_us*/) noexcept {
    return std::nullopt;
}

}  // namespace sniffer
