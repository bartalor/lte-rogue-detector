#include "db.hpp"

#include <stdexcept>

namespace sniffer {

Db::Db(const std::string& path) {
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        std::string msg = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        throw std::runtime_error("sqlite3_open: " + msg);
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

void Db::insert_message(const ExtractedFields& /*fields*/) {
    // implementation pending
}

}  // namespace sniffer
