#include "db.hpp"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <stdexcept>

namespace sniffer {

namespace {

const char* kInsertSql =
    "INSERT INTO messages ("
    " ts, direction, nas_msg_type,"
    " identity_type, eea_selected, eia_selected, ue_eea_caps, ue_eia_caps,"
    " emm_cause, enb_ue_s1ap_id, mme_ue_s1ap_id"
    ") VALUES (?,?,?,?,?,?,?,?,?,?,?)";

const char* nas_msg_type_str(NasMessageType t) {
    switch (t) {
        case NasMessageType::AttachRequest: return "AttachRequest";
        case NasMessageType::AttachAccept: return "AttachAccept";
        case NasMessageType::AttachComplete: return "AttachComplete";
        case NasMessageType::AttachReject: return "AttachReject";
        case NasMessageType::DetachRequest: return "DetachRequest";
        case NasMessageType::TauRequest: return "TauRequest";
        case NasMessageType::TauAccept: return "TauAccept";
        case NasMessageType::TauReject: return "TauReject";
        case NasMessageType::IdentityRequest: return "IdentityRequest";
        case NasMessageType::IdentityResponse: return "IdentityResponse";
        case NasMessageType::AuthenticationRequest: return "AuthenticationRequest";
        case NasMessageType::AuthenticationResponse: return "AuthenticationResponse";
        case NasMessageType::AuthenticationReject: return "AuthenticationReject";
        case NasMessageType::AuthenticationFailure: return "AuthenticationFailure";
        case NasMessageType::SecurityModeCommand: return "SecurityModeCommand";
        case NasMessageType::SecurityModeComplete: return "SecurityModeComplete";
        case NasMessageType::SecurityModeReject: return "SecurityModeReject";
        case NasMessageType::Unknown: return "Unknown";
    }
    return "Unknown";
}

const char* identity_kind_str(EpsMobileIdentity::Kind k) {
    switch (k) {
        case EpsMobileIdentity::Kind::Imsi: return "IMSI";
        case EpsMobileIdentity::Kind::Guti: return "GUTI";
        case EpsMobileIdentity::Kind::Imei: return "IMEI";
        case EpsMobileIdentity::Kind::Other: return "Other";
    }
    return "Other";
}

// S1AP procedure codes that imply direction. 12 = InitialUEMessage,
// 13 = UplinkNASTransport, 11 = DownlinkNASTransport.
std::optional<const char*> direction_for_proc(std::uint32_t proc) {
    switch (proc) {
        case 11: return "DL";
        case 12:
        case 13: return "UL";
        default: return std::nullopt;
    }
}

// Format ts_us as ISO 8601 UTC with microsecond precision.
std::string format_ts(std::uint64_t ts_us) {
    const std::time_t secs = static_cast<std::time_t>(ts_us / 1'000'000ull);
    const unsigned micros = static_cast<unsigned>(ts_us % 1'000'000ull);
    std::tm tm{};
    gmtime_r(&secs, &tm);
    char buf[96];
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02d-%02dT%02d:%02d:%02d.%06uZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, micros);
    return std::string(buf);
}

void bind_text(sqlite3_stmt* st, int idx, const std::string& s) {
    sqlite3_bind_text(st, idx, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT);
}

void bind_opt_int(sqlite3_stmt* st, int idx, std::optional<std::uint32_t> v) {
    if (v) sqlite3_bind_int64(st, idx, static_cast<sqlite3_int64>(*v));
    else sqlite3_bind_null(st, idx);
}

void bind_opt_u8(sqlite3_stmt* st, int idx, std::optional<std::uint8_t> v) {
    if (v) sqlite3_bind_int(st, idx, *v);
    else sqlite3_bind_null(st, idx);
}

}  // namespace

Db::Db(const std::string& path) {
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        std::string msg = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        throw std::runtime_error("sqlite3_open: " + msg);
    }
    sqlite3_exec(db_, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);
    if (sqlite3_prepare_v2(db_, kInsertSql, -1, &insert_stmt_, nullptr) != SQLITE_OK) {
        std::string msg = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        throw std::runtime_error("sqlite3_prepare insert: " + msg);
    }
}

Db::Db(Db&& other) noexcept : db_(other.db_), insert_stmt_(other.insert_stmt_) {
    other.db_ = nullptr;
    other.insert_stmt_ = nullptr;
}

Db& Db::operator=(Db&& other) noexcept {
    if (this != &other) {
        if (insert_stmt_) sqlite3_finalize(insert_stmt_);
        if (db_) sqlite3_close(db_);
        db_ = other.db_;
        insert_stmt_ = other.insert_stmt_;
        other.db_ = nullptr;
        other.insert_stmt_ = nullptr;
    }
    return *this;
}

Db::~Db() {
    if (insert_stmt_) sqlite3_finalize(insert_stmt_);
    if (db_) sqlite3_close(db_);
}

void Db::begin() {
    sqlite3_exec(db_, "BEGIN", nullptr, nullptr, nullptr);
}

void Db::commit() {
    sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
}

void Db::insert_message(const ExtractedFields& f) {
    // Skip messages we can't place a direction on. The schema's CHECK requires
    // direction IN ('UL','DL'); without an S1AP procedure code (e.g. raw NAS
    // from DLT_USER_1 captures) we have no signal for it.
    if (!f.s1ap_procedure_code) return;
    auto dir = direction_for_proc(*f.s1ap_procedure_code);
    if (!dir) return;
    if (f.nas.type == NasMessageType::Unknown) return;

    sqlite3_stmt* st = insert_stmt_;
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);

    const std::string ts = format_ts(f.ts_us);
    bind_text(st, 1, ts);
    sqlite3_bind_text(st, 2, *dir, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, nas_msg_type_str(f.nas.type), -1, SQLITE_STATIC);

    if (f.nas.mobile_identity) {
        sqlite3_bind_text(st, 4,
                          identity_kind_str(f.nas.mobile_identity->kind), -1,
                          SQLITE_STATIC);
    } else {
        sqlite3_bind_null(st, 4);
    }
    bind_opt_u8(st, 5, f.nas.selected_eea);
    bind_opt_u8(st, 6, f.nas.selected_eia);
    bind_opt_u8(st, 7, f.nas.ue_eea_caps);
    bind_opt_u8(st, 8, f.nas.ue_eia_caps);
    bind_opt_u8(st, 9, f.nas.emm_cause);
    bind_opt_int(st, 10, f.enb_ue_s1ap_id);
    bind_opt_int(st, 11, f.mme_ue_s1ap_id);

    if (sqlite3_step(st) != SQLITE_DONE) {
        throw std::runtime_error(
            std::string("sqlite3_step insert: ") + sqlite3_errmsg(db_));
    }
}

}  // namespace sniffer
