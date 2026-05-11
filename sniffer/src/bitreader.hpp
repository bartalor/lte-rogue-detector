#pragma once

#include <cstdint>
#include <cstddef>
#include <stdexcept>

namespace sniffer {

class BitReader {
public:
    BitReader(const std::uint8_t* data, std::size_t len) noexcept;

    std::uint64_t read_bits(std::size_t n);
    std::uint8_t read_u8();
    std::uint16_t read_u16_be();
    void skip_bits(std::size_t n);
    void align_to_byte();

    std::size_t bits_remaining() const noexcept;
    bool eof() const noexcept;

private:
    const std::uint8_t* data_;
    std::size_t len_;
    std::size_t bit_pos_{0};
};

struct ReadError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

}  // namespace sniffer
