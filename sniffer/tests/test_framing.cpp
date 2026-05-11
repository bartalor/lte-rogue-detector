#include "framing.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using sniffer::ByteSpan;
using sniffer::link_payloads;
using sniffer::LinkPayloadKind;
using sniffer::sll_to_s1ap_payloads;

namespace {

void append_u16_be(std::vector<std::uint8_t>& v, std::uint16_t x) {
    v.push_back(static_cast<std::uint8_t>(x >> 8));
    v.push_back(static_cast<std::uint8_t>(x & 0xff));
}

void append_u32_be(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>(x >> 24));
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xff));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xff));
    v.push_back(static_cast<std::uint8_t>(x & 0xff));
}

// Build SLL header + IPv4 header + SCTP common header + DATA chunk wrapping
// `payload` with given PPID.
std::vector<std::uint8_t> build_sll_sctp(
    const std::vector<std::uint8_t>& payload, std::uint32_t ppid) {
    std::vector<std::uint8_t> pkt;
    // SLL (16 bytes): pkt_type(2) ll_addr_type(2) ll_addr_len(2) addr(8) proto(2)
    pkt.resize(14, 0);
    append_u16_be(pkt, 0x0800);  // IPv4

    const std::size_t chunk_payload_len = payload.size();
    const std::size_t chunk_total = 16 + chunk_payload_len;
    const std::size_t chunk_padded = (chunk_total + 3u) & ~std::size_t{3};
    const std::size_t sctp_total = 12 + chunk_padded;
    const std::size_t ip_total = 20 + sctp_total;

    // IPv4 (20 bytes)
    pkt.push_back(0x45);            // version=4, IHL=5
    pkt.push_back(0x00);            // TOS
    append_u16_be(pkt, static_cast<std::uint16_t>(ip_total));
    append_u16_be(pkt, 0);          // id
    append_u16_be(pkt, 0);          // flags+frag
    pkt.push_back(64);              // TTL
    pkt.push_back(132);             // SCTP
    append_u16_be(pkt, 0);          // checksum
    append_u32_be(pkt, 0x0a000001); // src
    append_u32_be(pkt, 0x0a000002); // dst

    // SCTP common header (12 bytes): src_port(2) dst_port(2) vtag(4) checksum(4)
    append_u16_be(pkt, 36412);
    append_u16_be(pkt, 36412);
    append_u32_be(pkt, 0xdeadbeef);
    append_u32_be(pkt, 0);

    // DATA chunk (16 bytes header + payload + padding)
    pkt.push_back(0);  // type=DATA
    pkt.push_back(3);  // flags B|E|U
    append_u16_be(pkt, static_cast<std::uint16_t>(chunk_total));
    append_u32_be(pkt, 1);                   // TSN
    append_u16_be(pkt, 0);                   // stream id
    append_u16_be(pkt, 0);                   // stream seq
    append_u32_be(pkt, ppid);
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    while (pkt.size() < 14 + 2 + 20 + sctp_total) pkt.push_back(0);
    return pkt;
}

}  // namespace

TEST(Framing, RawNasPassesThroughLinktype148) {
    const std::vector<std::uint8_t> pdu = {0x07, 0x41, 0x71};
    auto out = link_payloads(148, pdu.data(), pdu.size());
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].kind, LinkPayloadKind::RawNas);
    EXPECT_EQ(out[0].span.data, pdu.data());
    EXPECT_EQ(out[0].span.len, pdu.size());
}

TEST(Framing, SllSctpReturnsS1apChunkPayload) {
    const std::vector<std::uint8_t> s1ap = {0xab, 0xcd, 0xef};
    auto pkt = build_sll_sctp(s1ap, 18);
    auto out = link_payloads(113, pkt.data(), pkt.size());
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].kind, LinkPayloadKind::S1apPdu);
    ASSERT_EQ(out[0].span.len, s1ap.size());
    EXPECT_EQ(out[0].span.data[0], 0xab);
    EXPECT_EQ(out[0].span.data[2], 0xef);
}

TEST(Framing, NonS1apPpidIsIgnored) {
    const std::vector<std::uint8_t> payload = {0x00, 0x01, 0x02};
    auto pkt = build_sll_sctp(payload, 0);  // PPID 0, not S1AP
    auto out = sll_to_s1ap_payloads(pkt.data(), pkt.size());
    EXPECT_TRUE(out.empty());
}

TEST(Framing, UnknownLinktypeReturnsEmpty) {
    const std::vector<std::uint8_t> data(100, 0);
    auto out = link_payloads(1 /* Ethernet */, data.data(), data.size());
    EXPECT_TRUE(out.empty());
}

TEST(Framing, TruncatedSllIsSafe) {
    const std::vector<std::uint8_t> data(8, 0);
    auto out = link_payloads(113, data.data(), data.size());
    EXPECT_TRUE(out.empty());
}
