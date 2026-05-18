#include "ingest.hpp"

#include "framing.hpp"
#include "nas.hpp"
#include "s1ap.hpp"

namespace sniffer {

namespace {

void emit_nas(const DecodedNasMessage& nas, std::uint64_t ts_us,
              std::vector<ExtractedFields>& out) {
    if (nas.type == NasMessageType::Unknown) return;
    ExtractedFields f{};
    f.ts_us = ts_us;
    f.nas = nas;
    out.push_back(std::move(f));
}

void emit_s1ap(const S1apPeel& peel, std::uint64_t ts_us,
               std::vector<ExtractedFields>& out) {
    auto nas = decode_nas(peel.nas_pdu);
    if (!nas || nas->type == NasMessageType::Unknown) return;
    ExtractedFields f{};
    f.ts_us = ts_us;
    f.s1ap_procedure_code = peel.procedure_code;
    f.enb_ue_s1ap_id = peel.enb_ue_s1ap_id;
    f.mme_ue_s1ap_id = peel.mme_ue_s1ap_id;
    f.cell_id = peel.cell_id;
    f.plmn_bcd = peel.plmn;
    f.nas = *nas;
    out.push_back(std::move(f));
}

}  // namespace

std::vector<ExtractedFields> ingest_packet(
    int linktype, const std::uint8_t* data, std::size_t len,
    std::uint64_t ts_us) noexcept {
    std::vector<ExtractedFields> out;
    for (const auto& lp : link_payloads(linktype, data, len)) {
        if (lp.kind == LinkPayloadKind::RawNas) {
            if (auto nas = decode_nas(lp.span)) emit_nas(*nas, ts_us, out);
        } else if (lp.kind == LinkPayloadKind::S1apPdu) {
            if (auto peel = peel_s1ap(lp.span)) emit_s1ap(*peel, ts_us, out);
        }
    }
    return out;
}

}  // namespace sniffer
