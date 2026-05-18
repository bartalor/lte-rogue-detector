#include "s1ap.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using sniffer::ByteSpan;
using sniffer::peel_s1ap;

namespace {

// Minimal APER-aware bit writer for synthesizing S1AP test vectors.
class BitWriter {
public:
    void put_bits(std::uint64_t v, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i) {
            const std::uint64_t bit = (v >> (n - 1 - i)) & 1u;
            const std::size_t byte = bit_pos_ / 8;
            const std::size_t off = 7 - (bit_pos_ % 8);
            if (byte >= buf_.size()) buf_.push_back(0);
            buf_[byte] |= static_cast<std::uint8_t>(bit << off);
            ++bit_pos_;
        }
    }
    void align() {
        const std::size_t rem = bit_pos_ % 8;
        if (rem != 0) bit_pos_ += (8 - rem);
        while (buf_.size() * 8 < bit_pos_) buf_.push_back(0);
    }
    void put_u8(std::uint8_t v) { align(); buf_.push_back(v); bit_pos_ += 8; }
    void put_u16_be(std::uint16_t v) {
        align();
        buf_.push_back(static_cast<std::uint8_t>(v >> 8));
        buf_.push_back(static_cast<std::uint8_t>(v & 0xff));
        bit_pos_ += 16;
    }
    void put_octets(const std::vector<std::uint8_t>& v) {
        align();
        for (auto b : v) buf_.push_back(b);
        bit_pos_ += v.size() * 8;
    }
    // APER length determinant (short form for <= 127).
    void put_len_short(std::uint32_t n) {
        align();
        if (n > 127) throw std::runtime_error("test helper: use short form only");
        buf_.push_back(static_cast<std::uint8_t>(n));
        bit_pos_ += 8;
    }
    const std::vector<std::uint8_t>& data() const { return buf_; }

private:
    std::vector<std::uint8_t> buf_;
    std::size_t bit_pos_{0};
};

// Encode one ProtocolIE-Field carrying an INTEGER value (eNB-UE-S1AP-ID, etc.).
// Open-type value is the big-endian integer octets directly (no inner length).
std::vector<std::uint8_t> encode_int_ie(std::uint16_t ie_id, std::uint32_t value,
                                        std::size_t value_bytes) {
    BitWriter w;
    w.put_u16_be(ie_id);
    w.put_bits(0, 2);  // criticality
    std::vector<std::uint8_t> open;
    for (std::size_t i = 0; i < value_bytes; ++i) {
        const std::size_t shift = (value_bytes - 1 - i) * 8;
        open.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
    }
    w.put_len_short(static_cast<std::uint32_t>(open.size()));
    w.put_octets(open);
    return w.data();
}

// Encode an EUTRAN-CGI IE (id 100) carrying a fixed 8-byte value:
//   0x00  -- SEQUENCE extension marker (top bit) + 7 pad bits, byte-aligned
//   3 PLMN octets
//   4 octets holding the 28-bit cell-ID left-aligned (low 4 bits padding)
// The wrapping ProtocolIE-Field encoding is: id(16) crit(2) length(LV) octets.
std::vector<std::uint8_t> encode_eutran_cgi_ie(
    std::uint8_t plmn0, std::uint8_t plmn1, std::uint8_t plmn2,
    std::uint32_t cell_id_28) {
    BitWriter w;
    w.put_u16_be(100);  // EUTRAN-CGI
    w.put_bits(0, 2);   // criticality: ignore
    std::vector<std::uint8_t> open;
    open.push_back(0x00);
    open.push_back(plmn0);
    open.push_back(plmn1);
    open.push_back(plmn2);
    const std::uint32_t shifted = (cell_id_28 & 0x0fffffffu) << 4;
    open.push_back(static_cast<std::uint8_t>((shifted >> 24) & 0xff));
    open.push_back(static_cast<std::uint8_t>((shifted >> 16) & 0xff));
    open.push_back(static_cast<std::uint8_t>((shifted >> 8) & 0xff));
    open.push_back(static_cast<std::uint8_t>(shifted & 0xff));
    w.put_len_short(static_cast<std::uint32_t>(open.size()));
    w.put_octets(open);
    return w.data();
}

std::vector<std::uint8_t> encode_nas_ie(const std::vector<std::uint8_t>& nas) {
    BitWriter w;
    w.put_u16_be(26);  // NAS-PDU
    w.put_bits(0, 2);  // criticality
    // Open-type value: 1 APER length octet for the OCTET STRING, then octets.
    std::vector<std::uint8_t> open;
    open.push_back(static_cast<std::uint8_t>(nas.size()));
    open.insert(open.end(), nas.begin(), nas.end());
    w.put_len_short(static_cast<std::uint32_t>(open.size()));
    w.put_octets(open);
    return w.data();
}

// Wrap a sequence of IE-Field encodings into an InitiatingMessage with the
// given procedureCode.
std::vector<std::uint8_t> encode_initiating_message(
    std::uint8_t procedure_code,
    const std::vector<std::vector<std::uint8_t>>& ies) {
    // The procedure body (e.g. InitialUEMessage) is an extensible SEQUENCE
    // wrapping the ProtocolIE-Container, so APER prepends a 1-bit extension
    // marker. After the marker we align before the count.
    BitWriter body;
    body.put_bits(0, 1);  // procedure-body extension marker
    body.align();
    body.put_u16_be(static_cast<std::uint16_t>(ies.size()));
    for (const auto& ie : ies) body.put_octets(ie);
    const std::vector<std::uint8_t>& container = body.data();

    BitWriter w;
    w.put_bits(0, 1);  // S1AP-PDU extension bit
    w.put_bits(0, 2);  // CHOICE index: initiatingMessage
    w.put_u8(procedure_code);
    w.put_bits(0, 2);  // criticality
    w.put_len_short(static_cast<std::uint32_t>(container.size()));
    w.put_octets(container);
    return w.data();
}

}  // namespace

TEST(S1ap, InitialUEMessageExtractsEnbIdAndNas) {
    const std::vector<std::uint8_t> nas = {0x07, 0x41, 0x71};
    auto pdu = encode_initiating_message(
        12,
        {encode_int_ie(8, 0x123456, 3), encode_nas_ie(nas)});
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    ASSERT_TRUE(peel.has_value());
    EXPECT_EQ(peel->procedure_code, 12u);
    ASSERT_TRUE(peel->enb_ue_s1ap_id.has_value());
    EXPECT_EQ(*peel->enb_ue_s1ap_id, 0x123456u);
    EXPECT_FALSE(peel->mme_ue_s1ap_id.has_value());
    ASSERT_EQ(peel->nas_pdu.len, nas.size());
    EXPECT_EQ(peel->nas_pdu.data[0], 0x07);
    EXPECT_EQ(peel->nas_pdu.data[2], 0x71);
}

TEST(S1ap, DownlinkNASTransportCarriesBothIds) {
    const std::vector<std::uint8_t> nas = {0x27, 0x00};
    auto pdu = encode_initiating_message(
        11,
        {encode_int_ie(0, 0xdeadbeef, 4),
         encode_int_ie(8, 0x7fffff, 3),
         encode_nas_ie(nas)});
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    ASSERT_TRUE(peel.has_value());
    EXPECT_EQ(peel->procedure_code, 11u);
    ASSERT_TRUE(peel->mme_ue_s1ap_id.has_value());
    EXPECT_EQ(*peel->mme_ue_s1ap_id, 0xdeadbeefu);
    ASSERT_TRUE(peel->enb_ue_s1ap_id.has_value());
    EXPECT_EQ(*peel->enb_ue_s1ap_id, 0x7fffffu);
    EXPECT_EQ(peel->nas_pdu.len, nas.size());
}

TEST(S1ap, UplinkNASTransportIsAccepted) {
    const std::vector<std::uint8_t> nas = {0x07, 0x42};
    auto pdu = encode_initiating_message(13, {encode_nas_ie(nas)});
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    ASSERT_TRUE(peel.has_value());
    EXPECT_EQ(peel->procedure_code, 13u);
}

TEST(S1ap, UnrelatedProcedureIsRejected) {
    const std::vector<std::uint8_t> nas = {0x07};
    auto pdu = encode_initiating_message(9, {encode_nas_ie(nas)});  // Paging
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    EXPECT_FALSE(peel.has_value());
}

TEST(S1ap, MissingNasPduReturnsNullopt) {
    auto pdu = encode_initiating_message(12, {encode_int_ie(8, 1, 1)});
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    EXPECT_FALSE(peel.has_value());
}

TEST(S1ap, InitialUEMessageExtractsEutranCgi) {
    const std::vector<std::uint8_t> nas = {0x07, 0x41, 0x71};
    auto pdu = encode_initiating_message(
        12,
        {encode_int_ie(8, 0x123456, 3),
         encode_nas_ie(nas),
         encode_eutran_cgi_ie(0x00, 0xf1, 0x10, 0x019B)});
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    ASSERT_TRUE(peel.has_value());
    ASSERT_TRUE(peel->cell_id.has_value());
    EXPECT_EQ(*peel->cell_id, 0x019Bu);
    ASSERT_TRUE(peel->plmn.has_value());
    EXPECT_EQ((*peel->plmn)[0], 0x00);
    EXPECT_EQ((*peel->plmn)[1], 0xf1);
    EXPECT_EQ((*peel->plmn)[2], 0x10);
}

TEST(S1ap, DownlinkNASTransportHasNoCellInfo) {
    const std::vector<std::uint8_t> nas = {0x27, 0x00};
    auto pdu = encode_initiating_message(
        11,
        {encode_int_ie(0, 0xdeadbeef, 4),
         encode_int_ie(8, 0x7fffff, 3),
         encode_nas_ie(nas)});
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    ASSERT_TRUE(peel.has_value());
    EXPECT_FALSE(peel->cell_id.has_value());
    EXPECT_FALSE(peel->plmn.has_value());
}

TEST(S1ap, TruncatedPduIsSafe) {
    const std::vector<std::uint8_t> nas = {0x07, 0x41, 0x71};
    auto pdu = encode_initiating_message(
        12, {encode_int_ie(8, 1, 1), encode_nas_ie(nas)});
    pdu.resize(pdu.size() - 2);
    auto peel = peel_s1ap(ByteSpan{pdu.data(), pdu.size()});
    EXPECT_FALSE(peel.has_value());
}
