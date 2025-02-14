// This file should be removed since all tests have been migrated to glaze_meta_test.cpp

#include "../utils/glaze_meta.hpp"

TEST(JsonMigration, basic_types)
{
    // Test basic type conversions
    const auto json = R"({
        "uint": "0x123",
        "int": "-0x123",
        "bytes": "0xdeadbeef",
        "address": "0x1234567890123456789012345678901234567890"
    })";

    const auto result = glz::read_json<glz::json_t>(json).value();
    EXPECT_EQ(glz::read<uint64_t>(result["uint"]), 0x123);
    // ... rest of test
} 