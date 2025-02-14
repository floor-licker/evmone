// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gmock/gmock.h>
#include <test/statetest/statetest.hpp>
#include <test/utils/utils.hpp>
#include "../utils/glaze_meta.hpp"

using namespace evmone;
using namespace evmone::test;
using namespace testing;

TEST(statetest_loader, load_empty_test)
{
    std::istringstream s{"{}"};
    const auto json = std::string{std::istreambuf_iterator<char>(s), {}};
    const auto result = glz::read_json<std::vector<StateTransitionTest>>(json);
    EXPECT_EQ(result.value().size(), 0);
}

TEST(statetest_loader, load_multi_test)
{
    std::istringstream s{R"({
      "T1": {
        "pre": {},
        "transaction": {"gasPrice": "","sender": "","to": "","data": null,
          "gasLimit": "0","value": null,"nonce" : "0"},
        "post": {},
        "env": {"currentNumber": "0","currentTimestamp": "0",
          "currentGasLimit": "0","currentCoinbase": ""}
      },
      "T2": {
        "pre": {},
        "transaction": {"gasPrice": "","sender": "","to": "","data": null,
          "gasLimit": "0","value": null,"nonce" : "0"},
        "post": {},
        "env": {"currentNumber": "0","currentTimestamp": "0",
          "currentGasLimit": "0","currentCoinbase": ""}
      }
    })"};
    const auto json = std::string{std::istreambuf_iterator<char>(s), {}};
    const auto tests = glz::read_json<std::vector<StateTransitionTest>>(json).value();
    ASSERT_EQ(tests.size(), 2);
    EXPECT_EQ(tests[0].name, "T1");
    EXPECT_EQ(tests[1].name, "T2");
}

TEST(statetest_loader, load_minimal_test)
{
    std::istringstream s{R"({
        "test": {
            "pre": {},
            "transaction": {
                "gasPrice": "",
                "sender": "",
                "to": "",
                "data": null,
                "gasLimit": "0",
                "value": null,
                "nonce" : "0"
            },
            "post": {
                "Cancun": []
            },
            "env": {
                "currentNumber": "0",
                "currentTimestamp": "0",
                "currentGasLimit": "0",
                "currentCoinbase": ""
            }
        }
    })"};
    const auto st = std::move(load_state_tests(s).at(0));
    // TODO: should add some comparison operator to State, BlockInfo, AccessList
    EXPECT_EQ(st.pre_state.size(), 0);
    EXPECT_EQ(st.cases[0].block.number, 0);
    EXPECT_EQ(st.cases[0].block.timestamp, 0);
    EXPECT_EQ(st.cases[0].block.gas_limit, 0);
    EXPECT_EQ(st.cases[0].block.coinbase, address{});
    EXPECT_EQ(st.cases[0].block.prev_randao, bytes32{});
    EXPECT_EQ(st.cases[0].block.base_fee, 0);
    EXPECT_EQ(st.multi_tx.type, test::TestMultiTransaction::Type::legacy);
    EXPECT_EQ(st.multi_tx.data, bytes{});
    EXPECT_EQ(st.multi_tx.gas_limit, 0);
    EXPECT_EQ(st.multi_tx.max_gas_price, 0);
    EXPECT_EQ(st.multi_tx.max_priority_gas_price, 0);
    EXPECT_EQ(st.multi_tx.sender, address{});
    EXPECT_EQ(st.multi_tx.to, std::nullopt);
    EXPECT_EQ(st.multi_tx.value, 0);
    EXPECT_EQ(st.multi_tx.nonce, 0);
    EXPECT_EQ(st.multi_tx.access_list.size(), 0);
    EXPECT_EQ(st.multi_tx.chain_id, 1);
    EXPECT_EQ(st.multi_tx.nonce, 0);
    EXPECT_EQ(st.multi_tx.r, 0);
    EXPECT_EQ(st.multi_tx.s, 0);
    EXPECT_EQ(st.multi_tx.v, 0);
    EXPECT_EQ(st.multi_tx.access_lists.size(), 0);
    EXPECT_EQ(st.multi_tx.inputs.size(), 0);
    EXPECT_EQ(st.multi_tx.gas_limits.size(), 1);
    EXPECT_EQ(st.multi_tx.gas_limits[0], 0);
    EXPECT_EQ(st.multi_tx.values.size(), 0);
    EXPECT_EQ(st.cases.size(), 1);
    EXPECT_EQ(st.cases[0].expectations.size(), 0);
    EXPECT_EQ(st.input_labels.size(), 0);
}

TEST(statetest_loader, validate_state_invalid_eof)
{
    TestState state{{0xadd4_address, {.code = "EF0001010000020001000103000100FEDA"_hex}}};
    EXPECT_THAT([&] { validate_state(state, EVMC_OSAKA); },
        ThrowsMessage<std::invalid_argument>(
            "EOF container at 0x000000000000000000000000000000000000add4 is invalid: "
            "zero_section_size"));
}

TEST(statetest_loader, validate_state_unexpected_eof)
{
    TestState state{{0xadd4_address, {.code = "EF00"_hex}}};
    EXPECT_THAT([&] { validate_state(state, EVMC_CANCUN); },
        ThrowsMessage<std::invalid_argument>(
            "unexpected code with EOF prefix at 0x000000000000000000000000000000000000add4"));
}

TEST(statetest_loader, validate_state_zero_storage_slot)
{
    TestState state{{0xadd4_address, {.storage = {{0x01_bytes32, 0x00_bytes32}}}}};
    EXPECT_THAT([&] { validate_state(state, EVMC_PRAGUE); },
        ThrowsMessage<std::invalid_argument>(
            "account 0x000000000000000000000000000000000000add4 contains invalid zero-value "
            "storage entry "
            "0x0000000000000000000000000000000000000000000000000000000000000001"));
}

TEST(StateTestLoader, parse_block_info)
{
    const auto json = R"({
        "currentNumber": "0x1",
        "currentTimestamp": "0x2",
        "currentGasLimit": "0x3",
        "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"
    })";

    const auto bi = glz::read_json<BlockInfo>(json).value();
    
    EXPECT_EQ(bi.number, 1);
    // ... rest of test
}
