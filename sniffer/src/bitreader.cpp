#include "bitreader.hpp"

namespace sniffer {

BitReader::BitReader(const std::uint8_t* data, std::size_t len) noexcept
    : data_(data), len_(len) {}

std::uint64_t BitReader::read_bits(std::size_t n) {
    if (n > 64) throw ReadError("read_bits: width > 64");
    if (bit_pos_ + n > len_ * 8) throw ReadError("read_bits: past end");
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        std::size_t byte = (bit_pos_ + i) / 8;
        std::size_t bit = 7 - ((bit_pos_ + i) % 8);
        v = (v << 1) | ((data_[byte] >> bit) & 1u);
    }
    bit_pos_ += n;
    return v;
}

std::uint8_t BitReader::read_u8() {
    return static_cast<std::uint8_t>(read_bits(8));
}

std::uint16_t BitReader::read_u16_be() {
    return static_cast<std::uint16_t>(read_bits(16));
}

void BitReader::skip_bits(std::size_t n) {
    if (bit_pos_ + n > len_ * 8) throw ReadError("skip_bits: past end");
    bit_pos_ += n;
}

void BitReader::align_to_byte() {
    std::size_t rem = bit_pos_ % 8;
    if (rem != 0) bit_pos_ += (8 - rem);
}

std::size_t BitReader::bits_remaining() const noexcept {
    return len_ * 8 > bit_pos_ ? (len_ * 8 - bit_pos_) : 0;
}

bool BitReader::eof() const noexcept {
    return bit_pos_ >= len_ * 8;
}

}  // namespace sniffer
