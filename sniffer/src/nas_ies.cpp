#include "nas_ies.hpp"

#include <cstdio>
#include <string>

namespace sniffer {

namespace {

// Append a BCD digit (0..9) to s. Returns false on filler nibble 0xf.
bool append_bcd(std::string& s, std::uint8_t nibble) {
    if (nibble == 0xf) return false;
    if (nibble > 9) return false;
    s.push_back(static_cast<char>('0' + nibble));
    return true;
}

// Parse an IMSI/IMEI digit string starting at the first identity byte.
// First byte: high nibble = digit 1, low nibble = (odd/even << 3) | type.
// Subsequent bytes: low nibble = next digit, high nibble = next-after digit.
// Odd-length identities end with filler 0xf in the last high nibble.
std::string parse_digits(const std::uint8_t* p, std::size_t len, bool odd) {
    std::string out;
    out.reserve(len * 2);
    append_bcd(out, p[0] >> 4);
    for (std::size_t i = 1; i < len; ++i) {
        append_bcd(out, p[i] & 0x0f);
        std::uint8_t hi = p[i] >> 4;
        // Last byte's high nibble is filler when length is odd.
        if (i == len - 1 && odd && hi == 0xf) break;
        append_bcd(out, hi);
    }
    return out;
}

}  // namespace

std::optional<EpsMobileIdentity> parse_eps_mobile_identity(ByteSpan ie) noexcept {
    if (ie.len < 1) return std::nullopt;
    const std::uint8_t first = ie.data[0];
    const std::uint8_t type = first & 0x07;
    const bool odd = (first & 0x08) != 0;

    EpsMobileIdentity id{};
    switch (type) {
        case 1: {  // IMSI
            id.kind = EpsMobileIdentity::Kind::Imsi;
            id.value = parse_digits(ie.data, ie.len, odd);
            return id;
        }
        case 2:    // IMEI
        case 3: {  // IMEISV
            id.kind = EpsMobileIdentity::Kind::Imei;
            id.value = parse_digits(ie.data, ie.len, odd);
            return id;
        }
        case 6: {  // GUTI
            // 1 (flags) + 3 (PLMN) + 2 (MME group) + 1 (MME code) + 4 (M-TMSI)
            if (ie.len < 11) return std::nullopt;
            id.kind = EpsMobileIdentity::Kind::Guti;
            // Render as PLMN-MMEgroup-MMEcode-MTMSI in hex; readable in alerts.
            char buf[64];
            std::snprintf(buf, sizeof(buf),
                          "%02x%02x%02x-%02x%02x-%02x-%02x%02x%02x%02x",
                          ie.data[1], ie.data[2], ie.data[3],
                          ie.data[4], ie.data[5],
                          ie.data[6],
                          ie.data[7], ie.data[8], ie.data[9], ie.data[10]);
            id.value = buf;
            return id;
        }
        default:
            id.kind = EpsMobileIdentity::Kind::Other;
            return id;
    }
}

std::optional<std::uint8_t> parse_emm_cause(ByteSpan ie) noexcept {
    if (ie.len < 1) return std::nullopt;
    return ie.data[0];
}

std::optional<NasSecurityAlgorithms> parse_nas_security_algorithms(ByteSpan ie) noexcept {
    if (ie.len < 1) return std::nullopt;
    NasSecurityAlgorithms a{};
    a.selected_eea = static_cast<std::uint8_t>((ie.data[0] >> 4) & 0x07);
    a.selected_eia = static_cast<std::uint8_t>(ie.data[0] & 0x07);
    return a;
}

std::optional<UeNetworkCapability> parse_ue_network_capability(ByteSpan ie) noexcept {
    if (ie.len < 2) return std::nullopt;
    UeNetworkCapability c{};
    c.eea_caps = ie.data[0];
    c.eia_caps = ie.data[1];
    return c;
}

}  // namespace sniffer
