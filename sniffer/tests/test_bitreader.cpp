#include "bitreader.hpp"

#include <gtest/gtest.h>

using sniffer::BitReader;
using sniffer::ReadError;

TEST(BitReader, ReadsBytesBigEndian) {
    const std::uint8_t buf[] = {0xab, 0xcd, 0xef};
    BitReader r(buf, sizeof(buf));
    EXPECT_EQ(r.read_u8(), 0xab);
    EXPECT_EQ(r.read_u16_be(), 0xcdef);
    EXPECT_TRUE(r.eof());
}

TEST(BitReader, ReadsSubByteFields) {
    // 0xa5 = 1010 0101 -> nibble high=0xa, low=0x5
    const std::uint8_t buf[] = {0xa5};
    BitReader r(buf, sizeof(buf));
    EXPECT_EQ(r.read_bits(4), 0xau);
    EXPECT_EQ(r.read_bits(4), 0x5u);
}

TEST(BitReader, AlignToByteAdvancesPastPartial) {
    const std::uint8_t buf[] = {0x80, 0x42};
    BitReader r(buf, sizeof(buf));
    EXPECT_EQ(r.read_bits(1), 1u);
    r.align_to_byte();
    EXPECT_EQ(r.read_u8(), 0x42);
}

TEST(BitReader, ThrowsOnReadPastEnd) {
    const std::uint8_t buf[] = {0x00};
    BitReader r(buf, sizeof(buf));
    EXPECT_THROW(r.read_bits(9), ReadError);
}
