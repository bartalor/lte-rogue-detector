#include "s1ap.hpp"

namespace sniffer {

std::optional<S1apPeel> peel_s1ap(ByteSpan /*s1ap*/) noexcept {
    return std::nullopt;
}

}  // namespace sniffer
