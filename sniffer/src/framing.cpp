#include "framing.hpp"

namespace sniffer {

namespace {

constexpr int kDltUser1 = 148;
constexpr int kDltLinuxSll = 113;

constexpr std::size_t kSllHeaderLen = 16;
constexpr std::size_t kIpv4MinHeaderLen = 20;
constexpr std::size_t kSctpCommonHeaderLen = 12;
constexpr std::size_t kSctpChunkHeaderLen = 4;

constexpr std::uint8_t kIpProtoSctp = 132;
constexpr std::uint8_t kSctpChunkData = 0;
constexpr std::uint32_t kPpidS1ap = 18;

constexpr std::uint16_t kSllProtoIpv4 = 0x0800;

std::uint16_t read_u16_be(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::uint32_t read_u32_be(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

// SCTP chunk lengths exclude trailing padding; chunks are 4-byte aligned.
std::size_t align4(std::size_t n) { return (n + 3u) & ~std::size_t{3}; }

}  // namespace

std::vector<ByteSpan> sll_to_s1ap_payloads(const std::uint8_t* pkt, std::size_t len) noexcept {
    std::vector<ByteSpan> out;
    if (len < kSllHeaderLen + kIpv4MinHeaderLen + kSctpCommonHeaderLen) return out;

    // SLL: bytes 14..15 = ethertype (network byte order).
    const std::uint16_t etype = read_u16_be(pkt + 14);
    if (etype != kSllProtoIpv4) return out;

    const std::uint8_t* ip = pkt + kSllHeaderLen;
    const std::size_t ip_avail = len - kSllHeaderLen;
    const std::uint8_t version = static_cast<std::uint8_t>(ip[0] >> 4);
    if (version != 4) return out;
    const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0f) * 4u;
    if (ihl < kIpv4MinHeaderLen || ihl > ip_avail) return out;
    const std::uint16_t total_len = read_u16_be(ip + 2);
    if (total_len > ip_avail) return out;
    if (ip[9] != kIpProtoSctp) return out;

    const std::uint8_t* sctp = ip + ihl;
    const std::size_t sctp_avail = total_len - ihl;
    if (sctp_avail < kSctpCommonHeaderLen) return out;

    std::size_t off = kSctpCommonHeaderLen;
    while (off + kSctpChunkHeaderLen <= sctp_avail) {
        const std::uint8_t chunk_type = sctp[off];
        const std::uint16_t chunk_len = read_u16_be(sctp + off + 2);
        if (chunk_len < kSctpChunkHeaderLen) break;
        if (off + chunk_len > sctp_avail) break;

        if (chunk_type == kSctpChunkData && chunk_len >= 16) {
            // DATA chunk header: type(1) flags(1) length(2) TSN(4) sid(2) seq(2) ppid(4) payload...
            const std::uint32_t ppid = read_u32_be(sctp + off + 12);
            if (ppid == kPpidS1ap) {
                const std::size_t payload_off = off + 16;
                const std::size_t payload_len = chunk_len - 16;
                out.push_back(ByteSpan{sctp + payload_off, payload_len});
            }
        }
        off += align4(chunk_len);
    }
    return out;
}

std::vector<LinkPayload> link_payloads(int linktype, const std::uint8_t* pkt, std::size_t len) noexcept {
    std::vector<LinkPayload> out;
    if (pkt == nullptr || len == 0) return out;

    if (linktype == kDltUser1) {
        out.push_back(LinkPayload{LinkPayloadKind::RawNas, ByteSpan{pkt, len}});
        return out;
    }
    if (linktype == kDltLinuxSll) {
        for (const auto& s : sll_to_s1ap_payloads(pkt, len)) {
            out.push_back(LinkPayload{LinkPayloadKind::S1apPdu, s});
        }
        return out;
    }
    return out;
}

}  // namespace sniffer
