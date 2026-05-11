#include "nas.hpp"
#include "bitreader.hpp"
#include "nas_ies.hpp"

namespace sniffer {

namespace {

constexpr std::uint8_t kPdEmm = 0x07;
constexpr std::size_t kSecurityHeaderLen = 6;  // SHT|PD + MAC(4) + seq(1)

bool is_known_msg_type(std::uint8_t t) {
    switch (t) {
        case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
        case 0x48: case 0x49: case 0x4b:
        case 0x52: case 0x53: case 0x54: case 0x5c:
        case 0x55: case 0x56:
        case 0x5d: case 0x5e: case 0x5f:
            return true;
        default:
            return false;
    }
}

// Read an LV-encoded field. Returns the value span and advances offset.
// Returns false if the encoded length runs past the buffer.
bool read_lv(const std::uint8_t* p, std::size_t len, std::size_t& off, ByteSpan& out) {
    if (off >= len) return false;
    std::size_t l = p[off++];
    if (off + l > len) return false;
    out = ByteSpan{p + off, l};
    off += l;
    return true;
}

void parse_attach_request(const std::uint8_t* p, std::size_t len, DecodedNasMessage& m) {
    // After PD/SHT(1) + msg type(1) at p[0..1], body starts at p[2].
    std::size_t off = 2;
    // Skip NAS key set ID + EPS attach type half-octets.
    if (off >= len) return;
    off += 1;
    ByteSpan mi{};
    if (!read_lv(p, len, off, mi)) return;
    if (auto id = parse_eps_mobile_identity(mi)) m.mobile_identity = *id;
    ByteSpan unc{};
    if (!read_lv(p, len, off, unc)) return;
    if (auto cap = parse_ue_network_capability(unc)) {
        m.ue_eea_caps = cap->eea_caps;
        m.ue_eia_caps = cap->eia_caps;
    }
}

void parse_identity_request(const std::uint8_t* p, std::size_t len, DecodedNasMessage& m) {
    if (len < 3) return;
    m.identity_request_type = static_cast<std::uint8_t>(p[2] & 0x07);
}

void parse_identity_response(const std::uint8_t* p, std::size_t len, DecodedNasMessage& m) {
    std::size_t off = 2;
    ByteSpan mi{};
    if (!read_lv(p, len, off, mi)) return;
    if (auto id = parse_eps_mobile_identity(mi)) m.mobile_identity = *id;
}

void parse_authentication_failure(const std::uint8_t* p, std::size_t len, DecodedNasMessage& m) {
    if (len < 3) return;
    m.emm_cause = p[2];
}

void parse_security_mode_command(const std::uint8_t* p, std::size_t len, DecodedNasMessage& m) {
    if (len < 3) return;
    ByteSpan algo{p + 2, 1};
    if (auto a = parse_nas_security_algorithms(algo)) {
        m.selected_eea = a->selected_eea;
        m.selected_eia = a->selected_eia;
    }
    // Replayed UE security capabilities follows the NAS key set ID half-octet at p[3].
    std::size_t off = 4;
    ByteSpan rep{};
    if (!read_lv(p, len, off, rep)) return;
    if (auto cap = parse_ue_network_capability(rep)) {
        m.ue_eea_caps = cap->eea_caps;
        m.ue_eia_caps = cap->eia_caps;
    }
}

void parse_tau_reject(const std::uint8_t* p, std::size_t len, DecodedNasMessage& m) {
    if (len < 3) return;
    m.emm_cause = p[2];
}

void dispatch(const std::uint8_t* p, std::size_t len, DecodedNasMessage& m) {
    m.type = static_cast<NasMessageType>(p[1]);
    switch (p[1]) {
        case 0x41: parse_attach_request(p, len, m); break;
        case 0x55: parse_identity_request(p, len, m); break;
        case 0x56: parse_identity_response(p, len, m); break;
        case 0x5c: parse_authentication_failure(p, len, m); break;
        case 0x5d: parse_security_mode_command(p, len, m); break;
        case 0x4b: parse_tau_reject(p, len, m); break;
        // Auth Req/Resp/Reject, Attach Accept/Complete/Reject, Detach, TAU
        // Request/Accept, SMC Complete/Reject: type alone is sufficient.
        default: break;
    }
}

}  // namespace

std::optional<DecodedNasMessage> decode_nas(ByteSpan pdu) noexcept {
    try {
        if (pdu.len < 2 || pdu.data == nullptr) return std::nullopt;
        const std::uint8_t pd = pdu.data[0] & 0x0f;
        const std::uint8_t sht = static_cast<std::uint8_t>((pdu.data[0] >> 4) & 0x0f);
        if (pd != kPdEmm) return std::nullopt;

        DecodedNasMessage m{};
        m.security_header_type = sht;
        m.raw.assign(pdu.data, pdu.data + pdu.len);

        if (sht == 0) {
            if (!is_known_msg_type(pdu.data[1])) {
                m.type = NasMessageType::Unknown;
                return m;
            }
            dispatch(pdu.data, pdu.len, m);
            return m;
        }

        // SHT 1..4 carry an inner NAS PDU after a 6-byte security header.
        if (sht >= 1 && sht <= 4) {
            if (pdu.len <= kSecurityHeaderLen + 1) return m;  // header only
            const std::uint8_t* inner = pdu.data + kSecurityHeaderLen;
            std::size_t inner_len = pdu.len - kSecurityHeaderLen;
            // The inner PDU is a plain NAS message: PD/SHT(=0) | msg type | ...
            const std::uint8_t inner_pd = inner[0] & 0x0f;
            if (inner_pd != kPdEmm) return m;
            if (!is_known_msg_type(inner[1])) return m;
            dispatch(inner, inner_len, m);
            return m;
        }

        return m;
    } catch (const ReadError&) {
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace sniffer
