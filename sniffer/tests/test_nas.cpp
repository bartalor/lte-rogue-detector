#include "nas.hpp"
#include "nas_ies.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using sniffer::ByteSpan;
using sniffer::decode_nas;
using sniffer::EpsMobileIdentity;
using sniffer::NasMessageType;
using sniffer::parse_eps_mobile_identity;
using sniffer::parse_nas_security_algorithms;
using sniffer::parse_ue_network_capability;

namespace {

ByteSpan span(const std::vector<std::uint8_t>& v) {
    return ByteSpan{v.data(), v.size()};
}

}  // namespace

// FBSDetector exp1_nas.pcap pkt0 — plain Attach Request carrying an IMSI.
TEST(NasDecoder, AttachRequestPlainImsi) {
    const std::vector<std::uint8_t> pdu = {
        0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x10,
        0x32, 0x54, 0x76, 0x98, 0x02, 0xf0, 0x70, 0x00,
        0x04, 0x02, 0x01, 0xd0, 0x11,
    };
    auto m = decode_nas(span(pdu));
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->type, NasMessageType::AttachRequest);
    EXPECT_EQ(m->security_header_type, 0);
    ASSERT_TRUE(m->mobile_identity.has_value());
    EXPECT_EQ(m->mobile_identity->kind, EpsMobileIdentity::Kind::Imsi);
    EXPECT_EQ(m->mobile_identity->value, "001010123456789");
    EXPECT_EQ(m->ue_eea_caps, 0xf0);
    EXPECT_EQ(m->ue_eia_caps, 0x70);
}

// Inner Security Mode Command wrapped in SHT=4 with the 6-byte security header.
TEST(NasDecoder, SecurityModeCommandUnderShtHeader) {
    const std::vector<std::uint8_t> pdu = {
        0x47, 0x00, 0x00, 0x00, 0x00, 0x00,  // SHT|PD + MAC + seq
        0x07, 0x5d,                            // inner: plain EMM, SMC
        0x01,                                  // selected algos: EEA0 | EIA1
        0x00,                                  // NAS key set ID half-octet
        0x02, 0xf0, 0x70,                      // replayed UE sec caps LV
    };
    auto m = decode_nas(span(pdu));
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->type, NasMessageType::SecurityModeCommand);
    EXPECT_EQ(m->security_header_type, 4);
    EXPECT_EQ(m->selected_eea, 0u);
    EXPECT_EQ(m->selected_eia, 1u);
    EXPECT_EQ(m->ue_eea_caps, 0xf0);
    EXPECT_EQ(m->ue_eia_caps, 0x70);
}

TEST(NasDecoder, IdentityRequestCarriesIdentityType) {
    // Asking for IMSI (identity type 1).
    const std::vector<std::uint8_t> pdu = {0x07, 0x55, 0x01};
    auto m = decode_nas(span(pdu));
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->type, NasMessageType::IdentityRequest);
    EXPECT_EQ(m->identity_request_type, 1u);
}

TEST(NasDecoder, AuthenticationFailureCarriesEmmCause) {
    // Cause 21 = synch failure.
    const std::vector<std::uint8_t> pdu = {0x07, 0x5c, 0x15};
    auto m = decode_nas(span(pdu));
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->type, NasMessageType::AuthenticationFailure);
    EXPECT_EQ(m->emm_cause, 0x15);
}

TEST(NasDecoder, RejectsNonEmmDiscriminator) {
    // PD = 0x02 (ESM), not EMM — decoder should return nullopt.
    const std::vector<std::uint8_t> pdu = {0x02, 0x41, 0x00};
    EXPECT_FALSE(decode_nas(span(pdu)).has_value());
}

TEST(NasDecoder, ShortBufferReturnsNullopt) {
    const std::vector<std::uint8_t> pdu = {0x07};
    EXPECT_FALSE(decode_nas(span(pdu)).has_value());
}

TEST(NasDecoder, UnknownMessageTypeYieldsUnknown) {
    const std::vector<std::uint8_t> pdu = {0x07, 0x7f, 0x00};
    auto m = decode_nas(span(pdu));
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->type, NasMessageType::Unknown);
}

// IE-level checks.

TEST(NasIes, MobileIdentityGutiRendersHex) {
    // GUTI: type=6, flags 0xf6; PLMN(3) 02 f8 39; MMEgrp(2) 01 02;
    // MMEcode 03; M-TMSI 0a 0b 0c 0d.
    const std::vector<std::uint8_t> ie = {
        0xf6, 0x02, 0xf8, 0x39, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d,
    };
    auto id = parse_eps_mobile_identity(ByteSpan{ie.data(), ie.size()});
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(id->kind, EpsMobileIdentity::Kind::Guti);
    EXPECT_EQ(id->value, "02f839-0102-03-0a0b0c0d");
}

TEST(NasIes, SecurityAlgorithmsSplitsNibbles) {
    const std::vector<std::uint8_t> ie = {0x32};  // EEA3, EIA2
    auto a = parse_nas_security_algorithms(ByteSpan{ie.data(), ie.size()});
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->selected_eea, 3u);
    EXPECT_EQ(a->selected_eia, 2u);
}

TEST(NasIes, UeNetworkCapabilityReadsBitmaps) {
    const std::vector<std::uint8_t> ie = {0xe0, 0x60};  // EEA0..2, EIA1..2
    auto c = parse_ue_network_capability(ByteSpan{ie.data(), ie.size()});
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c->eea_caps, 0xe0);
    EXPECT_EQ(c->eia_caps, 0x60);
}
