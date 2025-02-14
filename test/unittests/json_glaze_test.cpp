#include <gtest/gtest.h>
#include <glaze/glaze.hpp>
#include "../state/test_state.hpp"

using namespace evmone::test;

TEST(GlazeMigration, TestStateSerialize) {
    TestState state;
    TestAccount account{
        .nonce = 1,
        .balance = 1000,
        .storage = {{0x1_bytes32, 0x2_bytes32}},
        .code = bytes{0x60, 0x01}
    };
    state[0x1234_address] = account;
    
    // Serialize
    auto json = glz::write_json(state);
    
    // Deserialize
    TestState decoded;
    auto ec = glz::read_json(decoded, json);
    
    EXPECT_FALSE(ec);
    EXPECT_EQ(state, decoded);
}

TEST(GlazeMigration, TransactionSerialize) {
    state::Transaction tx{
        .sender = 0x1234_address,
        .nonce = 1,
        .max_gas_price = 1000,
        .gas_limit = 21000,
        .to = 0x5678_address,
        .value = 1,
        .data = bytes{0x60, 0x01}
    };
    
    // Serialize
    auto json = glz::write_json(tx);
    
    // Deserialize
    state::Transaction decoded;
    auto ec = glz::read_json(decoded, json);
    
    EXPECT_FALSE(ec);
    EXPECT_EQ(tx, decoded);
}

TEST(GlazeMigration, EOFValidationTest) {
    const std::string input = R"({
        "test1": {
            "vectors": {
                "case1": {
                    "code": "ef00",
                    "containerKind": "INITCODE",
                    "results": {
                        "Osaka": {
                            "result": true
                        }
                    }
                }
            }
        }
    })";
    
    auto tests = glz::read_json<std::vector<EOFValidationTest>>(input);
    
    ASSERT_EQ(tests.size(), 1);
    ASSERT_EQ(tests[0].name, "test1");
    ASSERT_EQ(tests[0].cases.size(), 1);
    
    const auto& test_case = tests[0].cases.at("case1");
    EXPECT_EQ(test_case.code, (bytes{0xef, 0x00}));
    EXPECT_EQ(test_case.kind, ContainerKind::initcode);
    ASSERT_EQ(test_case.expectations.size(), 1);
    EXPECT_EQ(test_case.expectations[0].rev, EVMC_OSAKA);
    EXPECT_TRUE(test_case.expectations[0].result);
}

TEST(GlazeMigration, T8NStateTest) {
    const std::string input = R"({
        "0x1234": {
            "nonce": "0x0",
            "balance": "0x1000",
            "code": "0x60016001",
            "storage": {
                "0x01": "0x02"
            }
        }
    })";
    
    auto state = glz::read_json<TestState>(input);
    
    ASSERT_EQ(state.size(), 1);
    const auto& account = state.at(0x1234_address);
    EXPECT_EQ(account.nonce, 0);
    EXPECT_EQ(account.balance, 0x1000);
    EXPECT_EQ(account.code, (bytes{0x60, 0x01, 0x60, 0x01}));
    EXPECT_EQ(account.storage.size(), 1);
    EXPECT_EQ(account.storage.at(0x01_bytes32), 0x02_bytes32);
}

TEST(GlazeMigration, T8NBlockInfo) {
    const std::string input = R"({
        "currentNumber": "0x1",
        "currentTimestamp": "0x100",
        "currentGasLimit": "0x1000000",
        "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
        "currentDifficulty": "0x20000",
        "parentBaseFee": "0x7"
    })";
    
    auto block = glz::read_json<state::BlockInfo>(input);
    
    EXPECT_EQ(block.number, 1);
    EXPECT_EQ(block.timestamp, 0x100);
    EXPECT_EQ(block.gas_limit, 0x1000000);
    EXPECT_EQ(block.coinbase, 0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba_address);
    EXPECT_EQ(block.difficulty, 0x20000);
}

TEST(GlazeMigration, TransactionReceiptTest) {
    const std::string input = R"({
        "transactionHash": "0x1234",
        "gasUsed": "0x5208",
        "cumulativeGasUsed": "0x5208",
        "contractAddress": null,
        "logsBloom": "0x00000000000000000000000000000000",
        "logs": [],
        "status": "0x1",
        "transactionIndex": "0x0"
    })";
    
    auto receipt = glz::read_json<state::TransactionReceipt>(input);
    
    EXPECT_EQ(receipt.gas_used, 0x5208);
    EXPECT_EQ(receipt.cumulative_gas_used, 0x5208);
    EXPECT_TRUE(receipt.logs.empty());
    EXPECT_EQ(receipt.transaction_index, 0);
}

TEST(GlazeMigration, RequestsTest) {
    const std::string input = R"({
        "data": "0x1234",
        "raw_data": "0x5678"
    })";
    
    auto request = glz::read_json<state::Requests>(input);
    
    EXPECT_EQ(request.data(), (bytes{0x12, 0x34}));
    EXPECT_EQ(request.raw_data, (bytes{0x56, 0x78}));
}

TEST(GlazeMigration, StateExportTest) {
    TestState state;
    TestAccount account{
        .nonce = 1,
        .balance = 1000,
        .storage = {{0x1_bytes32, 0x2_bytes32}},
        .code = bytes{0x60, 0x01}
    };
    state[0x1234_address] = account;
    
    auto json = to_json(state);
    
    // Verify exported JSON structure
    EXPECT_TRUE(json.contains(hex0x(0x1234_address)));
    const auto& j_acc = json[hex0x(0x1234_address)];
    EXPECT_EQ(j_acc["nonce"], "0x1");
    EXPECT_EQ(j_acc["balance"], "0x3e8");
    EXPECT_EQ(j_acc["code"], "0x6001");
    EXPECT_EQ(j_acc["storage"][hex0x(0x1_bytes32)], hex0x(0x2_bytes32));
}

TEST(GlazeMigration, ComplexStateTest) {
    const std::string input = R"({
        "env": {
            "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "currentDifficulty": "0x20000",
            "currentGasLimit": "0xff112233445566",
            "currentNumber": "1",
            "currentTimestamp": "1000",
            "currentBaseFee": "7"
        },
        "pre": {
            "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
                "nonce": "0",
                "balance": "1000000000000000000",
                "code": "",
                "storage": {}
            }
        },
        "transaction": {
            "data": ["0x"],
            "gasLimit": ["0x61a80"],
            "value": ["0x01"]
        }
    })";
    
    auto test = glz::read_json<StateTransitionTest>(input);
    
    EXPECT_EQ(test.pre_state.size(), 1);
    EXPECT_EQ(test.multi_tx.gas_limits.size(), 1);
    EXPECT_EQ(test.multi_tx.values.size(), 1);
}

TEST(GlazeMigration, NestedArraysTest) {
    const std::string input = R"({
        "transaction": {
            "data": ["0x", "0x1234", "0x5678"],
            "gasLimit": ["0x5208", "0x7530", "0x9c40"],
            "value": ["0x0", "0x1", "0x2"],
            "accessLists": [
                {
                    "address": "0x1234",
                    "storageKeys": ["0x01", "0x02"]
                },
                {
                    "address": "0x5678",
                    "storageKeys": ["0x03", "0x04"]
                }
            ]
        }
    })";
    
    auto test = glz::read_json<TestMultiTransaction>(input);
    
    ASSERT_EQ(test.inputs.size(), 3);
    ASSERT_EQ(test.gas_limits.size(), 3);
    ASSERT_EQ(test.values.size(), 3);
    ASSERT_EQ(test.access_lists.size(), 2);
    
    EXPECT_EQ(test.inputs[1], (bytes{0x12, 0x34}));
    EXPECT_EQ(test.gas_limits[1], 0x7530);
    EXPECT_EQ(test.values[1], 1);
    EXPECT_EQ(test.access_lists[0].address, 0x1234_address);
    EXPECT_EQ(test.access_lists[0].storage_keys[1], 0x02_bytes32);
}

TEST(GlazeMigration, TransactionParsingTest) {
    const std::string input = R"({
        "type": "0x02",
        "chainId": "0x01",
        "nonce": "0x00",
        "maxPriorityFeePerGas": "0x3b9aca00",
        "maxFeePerGas": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x1234567890123456789012345678901234567890",
        "value": "0x0de0b6b3a7640000",
        "input": "0x",
        "accessList": [
            {
                "address": "0x1234567890123456789012345678901234567890",
                "storageKeys": [
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                ]
            }
        ],
        "v": "0x01",
        "r": "0x1234567890123456789012345678901234567890123456789012345678901234",
        "s": "0x1234567890123456789012345678901234567890123456789012345678901234"
    })";
    
    auto tx = glz::read_json<state::Transaction>(input);
    
    EXPECT_EQ(tx.type, state::Transaction::Type::access_list);
    EXPECT_EQ(tx.chain_id, 1);
    EXPECT_EQ(tx.nonce, 0);
    EXPECT_EQ(tx.max_priority_gas_price, 0x3b9aca00);
    EXPECT_EQ(tx.gas_limit, 0x5208);
    EXPECT_EQ(tx.value, 0x0de0b6b3a7640000_u256);
    EXPECT_TRUE(tx.data.empty());
    ASSERT_EQ(tx.access_list.size(), 1);
    EXPECT_EQ(tx.access_list[0].storage_keys.size(), 1);
}

TEST(GlazeMigration, AuthorizationListTest) {
    const std::string input = R"({
        "type": "0x03",
        "chainId": "0x01",
        "nonce": "0x00",
        "maxPriorityFeePerGas": "0x3b9aca00",
        "maxFeePerGas": "0x3b9aca00",
        "gas": "0x5208",
        "authorizationList": {
            "chain_id": "0x01",
            "signer": "0x1234567890123456789012345678901234567890",
            "nonce": "0x00",
            "code_hash": "0x1234567890123456789012345678901234567890123456789012345678901234",
            "r": "0x1234567890123456789012345678901234567890123456789012345678901234",
            "s": "0x1234567890123456789012345678901234567890123456789012345678901234",
            "v": "0x1b"
        }
    })";
    
    auto tx = glz::read_json<state::Transaction>(input);
    
    EXPECT_EQ(tx.type, state::Transaction::Type::set_code);
    EXPECT_EQ(tx.chain_id, 1);
    EXPECT_EQ(tx.nonce, 0);
    EXPECT_EQ(tx.max_priority_gas_price, 0x3b9aca00);
    EXPECT_EQ(tx.gas_limit, 0x5208);
    ASSERT_TRUE(tx.authorization_list.has_value());
    EXPECT_EQ(tx.authorization_list->chain_id, 1);
    EXPECT_EQ(tx.authorization_list->nonce, 0);
    EXPECT_EQ(tx.authorization_list->v, 0x1b);
}

TEST(GlazeMigration, BlockInfoParsingTest) {
    const std::string input = R"({
        "currentNumber": "0x1",
        "currentTimestamp": "0x100",
        "parentTimestamp": "0x50",
        "currentGasLimit": "0x1000000",
        "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
        "currentDifficulty": "0x20000",
        "parentDifficulty": "0x10000",
        "parentUncleHash": "0x1234567890123456789012345678901234567890123456789012345678901234",
        "currentExcessBlobGas": "0x1000",
        "withdrawals": [
            {
                "index": "0x0",
                "validatorIndex": "0x1",
                "address": "0x1234567890123456789012345678901234567890",
                "amount": "0x1000"
            }
        ]
    })";
    
    auto block = from_json_with_rev(glz::read_json(input), EVMC_SHANGHAI);
    
    EXPECT_EQ(block.number, 1);
    EXPECT_EQ(block.timestamp, 0x100);
    EXPECT_EQ(block.parent_timestamp, 0x50);
    EXPECT_EQ(block.gas_limit, 0x1000000);
    EXPECT_EQ(block.coinbase, 0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba_address);
    EXPECT_EQ(block.difficulty, 0x20000);
    EXPECT_EQ(block.parent_difficulty, 0x10000);
    ASSERT_EQ(block.withdrawals.size(), 1);
    EXPECT_EQ(block.withdrawals[0].index, 0);
    EXPECT_EQ(block.withdrawals[0].amount, 0x1000);
} 