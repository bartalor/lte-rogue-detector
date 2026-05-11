#pragma once

#include "types.hpp"

#include <sqlite3.h>

#include <string>

namespace sniffer {

class Db {
public:
    explicit Db(const std::string& path);
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;
    Db(Db&&) noexcept;
    Db& operator=(Db&&) noexcept;
    ~Db();

    void begin();
    void commit();
    void insert_message(const ExtractedFields& fields);

private:
    sqlite3* db_{nullptr};
    sqlite3_stmt* insert_stmt_{nullptr};
};

}  // namespace sniffer
