#include "../utils/glaze_meta.hpp"
#include <gtest/gtest.h>

TEST(GlazeLoader, LoadUint64)
{
    EXPECT_EQ(glz::read_json<uint64_t>("\"0x00000005\"").value(), 5);
    EXPECT_EQ(glz::read_json<uint64_t>("\"5\"").value(), 5);
    EXPECT_EQ(glz::read_json<uint64_t>("7").value(), 7);

    EXPECT_EQ(glz::read_json<uint64_t>("\"0xffffffffffffffff\"").value(),
        std::numeric_limits<uint64_t>::max());
    EXPECT_THROW(glz::read_json<uint64_t>("\"0x10000000000000000\""), std::out_of_range);
    EXPECT_THROW(glz::read_json<uint64_t>("\"xyz\""), std::invalid_argument);
}

TEST(GlazeLoader, LoadInt64)
{
    EXPECT_EQ(glz::read_json<int64_t>("\"0x00000005\"").value(), 5);
    EXPECT_EQ(glz::read_json<int64_t>("\"-0x5\"").value(), -5);
    EXPECT_EQ(glz::read_json<int64_t>("\"-5\"").value(), -5);
    EXPECT_EQ(glz::read_json<int64_t>("-7").value(), -7);

    EXPECT_THROW(glz::read_json<int64_t>("\"0x10000000000000000\""), std::out_of_range);
    EXPECT_THROW(glz::read_json<int64_t>("\"xyz\""), std::invalid_argument);
} 