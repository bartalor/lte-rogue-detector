#include "s1ap.hpp"

#include "bitreader.hpp"

namespace sniffer {

namespace {

// S1AP procedure codes we care about (3GPP TS 36.413).
constexpr std::uint32_t kProcInitialUEMessage = 12;
constexpr std::uint32_t kProcDownlinkNASTransport = 11;
constexpr std::uint32_t kProcUplinkNASTransport = 13;

// ProtocolIE-IDs we extract.
constexpr std::uint32_t kIeMmeUeS1apId = 0;
constexpr std::uint32_t kIeEnbUeS1apId = 8;
constexpr std::uint32_t kIeNasPdu = 26;

// S1AP-PDU is a CHOICE of {initiatingMessage, successfulOutcome,
// unsuccessfulOutcome, ...}. We only handle initiatingMessage.
constexpr std::uint64_t kChoiceInitiatingMessage = 0;

// APER length determinant for general lengths (not fragmented):
//   0xxxxxxx          -> 0..127
//   10xxxxxx xxxxxxx  -> 0..16383
//   11xxxxxx          -> fragmented (16k * value bytes, then more)
// We do not handle fragmentation; NAS-PDU IEs fit easily under 16k.
std::uint32_t read_length_determinant(BitReader& br) {
    br.align_to_byte();
    const std::uint8_t b0 = br.read_u8();
    if ((b0 & 0x80) == 0) return b0 & 0x7f;
    if ((b0 & 0xc0) == 0x80) {
        const std::uint8_t b1 = br.read_u8();
        return (static_cast<std::uint32_t>(b0 & 0x3f) << 8) | b1;
    }
    throw ReadError("aper length: fragmented length not supported");
}

// Read a non-negative INTEGER constrained to [0, 2^bits - 1]. APER aligns to a
// byte boundary if the value occupies more than one byte (i.e. bits >= 8).
std::uint32_t read_uint(BitReader& br, std::size_t bits) {
    if (bits >= 8) br.align_to_byte();
    return static_cast<std::uint32_t>(br.read_bits(bits));
}

// Read `n` octets after byte-aligning. Returns a span into the underlying
// buffer; caller must ensure the BitReader outlives the span.
ByteSpan read_octet_span(BitReader& br, const std::uint8_t* base, std::size_t base_len,
                        std::uint32_t n) {
    br.align_to_byte();
    const std::size_t pos = (br.bits_remaining() == 0)
                                ? base_len
                                : base_len - br.bits_remaining() / 8;
    if (n > base_len - pos) throw ReadError("octet span: past end");
    br.skip_bits(static_cast<std::size_t>(n) * 8);
    return ByteSpan{base + pos, n};
}

// Decode the value of an INTEGER (0..maxValue) IE. For our IEs:
//   MME-UE-S1AP-ID: 0..2^32-1  -> length-prefixed, up to 4 bytes
//   eNB-UE-S1AP-ID: 0..2^24-1  -> length-prefixed, up to 3 bytes
// Both are encoded as: length determinant (in octets), then big-endian value.
std::uint32_t decode_ue_s1ap_id(ByteSpan v) {
    if (v.len == 0 || v.len > 4) throw ReadError("ue_s1ap_id: bad length");
    std::uint32_t out = 0;
    for (std::size_t i = 0; i < v.len; ++i) {
        out = (out << 8) | v.data[i];
    }
    return out;
}

void parse_ie(std::uint32_t ie_id, ByteSpan value, S1apPeel& peel) {
    switch (ie_id) {
        case kIeMmeUeS1apId:
            peel.mme_ue_s1ap_id = decode_ue_s1ap_id(value);
            break;
        case kIeEnbUeS1apId:
            peel.enb_ue_s1ap_id = decode_ue_s1ap_id(value);
            break;
        case kIeNasPdu:
            peel.nas_pdu = value;
            break;
        default:
            break;
    }
}

// ProtocolIE-Container ::= SEQUENCE (SIZE(0..65535)) OF ProtocolIE-Field
// Encoded as: count (16 bits, byte-aligned), then `count` IE fields.
//
// ProtocolIE-Field ::= SEQUENCE {
//     id          ProtocolIE-ID,     -- INTEGER (0..65535), 16 bits aligned
//     criticality Criticality,       -- ENUMERATED, 2 bits
//     value       <open type>        -- length-prefixed octets containing
//                                       the APER-encoded value
// }
void parse_ie_container(BitReader& br, S1apPeel& peel,
                        const std::uint8_t* base, std::size_t base_len) {
    br.align_to_byte();
    const std::uint32_t count = read_uint(br, 16);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint32_t ie_id = read_uint(br, 16);
        br.read_bits(2);  // criticality
        const std::uint32_t value_len = read_length_determinant(br);
        ByteSpan value = read_octet_span(br, base, base_len, value_len);

        // For NAS-PDU (OCTET STRING) the open-type value is the octets directly,
        // but most other IEs wrap an APER-encoded type inside their length-
        // prefixed open type. For the integer IEs we care about, the open-type
        // payload is itself an APER-encoded INTEGER: one length octet followed
        // by big-endian octets. Peel that prefix for the integer IEs.
        if (ie_id == kIeEnbUeS1apId || ie_id == kIeMmeUeS1apId) {
            if (value.len < 1) continue;
            const std::uint8_t int_len = value.data[0];
            if (int_len == 0 || std::size_t{int_len} + 1u > value.len) continue;
            parse_ie(ie_id, ByteSpan{value.data + 1, int_len}, peel);
        } else {
            parse_ie(ie_id, value, peel);
        }
    }
}

bool procedure_carries_nas(std::uint32_t code) {
    return code == kProcInitialUEMessage ||
           code == kProcDownlinkNASTransport ||
           code == kProcUplinkNASTransport;
}

}  // namespace

std::optional<S1apPeel> peel_s1ap(ByteSpan s1ap) noexcept {
    try {
        if (s1ap.data == nullptr || s1ap.len == 0) return std::nullopt;
        BitReader br(s1ap.data, s1ap.len);

        // S1AP-PDU CHOICE: 1 extension bit, then 2 bits for the choice index
        // (3 root alternatives). We only handle initiatingMessage (index 0).
        const std::uint64_t ext = br.read_bits(1);
        if (ext != 0) return std::nullopt;
        const std::uint64_t choice = br.read_bits(2);
        if (choice != kChoiceInitiatingMessage) return std::nullopt;

        // InitiatingMessage ::= SEQUENCE {
        //     procedureCode  ProcedureCode (0..255),
        //     criticality    Criticality,
        //     value          <open type containing the procedure's IEs>
        // }
        // No extension marker on InitiatingMessage in the root.
        const std::uint32_t proc = read_uint(br, 8);
        if (!procedure_carries_nas(proc)) return std::nullopt;
        br.read_bits(2);  // criticality
        const std::uint32_t value_len = read_length_determinant(br);

        // The open-type value contains the procedure's ProtocolIE-Container,
        // byte-aligned. Decode within those bounds.
        br.align_to_byte();
        const std::size_t consumed_bytes =
            s1ap.len - br.bits_remaining() / 8;
        if (value_len > s1ap.len - consumed_bytes) return std::nullopt;

        BitReader inner(s1ap.data + consumed_bytes, value_len);
        S1apPeel peel{};
        peel.procedure_code = proc;
        parse_ie_container(inner, peel, s1ap.data + consumed_bytes, value_len);

        if (peel.nas_pdu.len == 0) return std::nullopt;
        return peel;
    } catch (const ReadError&) {
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace sniffer
