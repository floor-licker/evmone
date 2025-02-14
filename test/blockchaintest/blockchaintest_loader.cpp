// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../statetest/statetest.hpp"
#include "../utils/utils.hpp"
#include "blockchaintest.hpp"
#include <glaze/glaze.hpp>

namespace evmone::test
{

namespace
{
template <typename T>
T load_if_exists(const json::value& j, std::string_view key)
{
    return json::get_optional<T>(j, key).value_or(T{});
}

template <typename T>
std::optional<T> load_optional(const json::value& j, std::string_view key)
{
    return json::get_optional<T>(j, key);
}
}  // namespace

template <>
BlockHeader from_json<BlockHeader>(const json::value& j)
{
    auto [parent_hash, coinbase, state_root, receipts_root, logs_bloom, number, gas_limit, 
          gas_used, timestamp, extra_data, hash, txs_root] = 
        glz::read<std::tuple<
            hash256, address, hash256, hash256, bytes, int64_t, int64_t,
            int64_t, int64_t, bytes, hash256, hash256
        >>(j, {
            "parentHash", "coinbase", "stateRoot", "receiptTrie", "bloom",
            "number", "gasLimit", "gasUsed", "timestamp", "extraData",
            "hash", "transactionsTrie"
        });

    return {
        .parent_hash = parent_hash,
        .coinbase = coinbase,
        .state_root = state_root,
        .receipts_root = receipts_root,
        .logs_bloom = state::bloom_filter_from_bytes(logs_bloom),
        .difficulty = load_if_exists<int64_t>(j, "difficulty"),
        .prev_randao = load_if_exists<bytes32>(j, "mixHash"),
        .block_number = number,
        .gas_limit = gas_limit,
        .gas_used = gas_used,
        .timestamp = timestamp,
        .extra_data = extra_data,
        .base_fee_per_gas = load_if_exists<uint64_t>(j, "baseFeePerGas"),
        .hash = hash,
        .transactions_root = txs_root,
        .withdrawal_root = load_if_exists<hash256>(j, "withdrawalsRoot"),
        .parent_beacon_block_root = load_if_exists<hash256>(j, "parentBeaconBlockRoot"),
        .blob_gas_used = load_optional<uint64_t>(j, "blobGasUsed"),
    };
}

template <>
Block from_json<Block>(const json::value& j)
{
    Block block;
    block.header = from_json<BlockHeader>(j.at("blockHeader"));

    if (auto txs = json::get_optional<json::value>(j, "transactions")) {
        for (const auto& tx : *txs) {
            block.transactions.push_back(from_json<state::Transaction>(tx));
        }
    }

    if (auto uncles = json::get_optional<json::value>(j, "uncleHeaders")) {
        for (const auto& uncle : *uncles) {
            block.ommers.push_back(from_json<BlockHeader>(uncle));
        }
    }

    if (auto withdrawals = json::get_optional<json::value>(j, "withdrawals")) {
        for (const auto& withdrawal : *withdrawals) {
            block.withdrawals.push_back(from_json<state::Withdrawal>(withdrawal));
        }
    }

    return block;
}

template <>
BlockchainTest from_json<BlockchainTest>(const json::value& j)
{
    BlockchainTest test;

    auto [network, seal_engine] = glz::read<std::tuple<std::string, std::string>>(
        j, {"network", "sealEngine"}
    );

    test.rev = to_rev(network);
    if (seal_engine != "NoProof")
        throw UnsupportedTestFeature("Unsupported seal engine: " + seal_engine);

    test.genesis_header = from_json<BlockHeader>(j.at("genesisBlockHeader"));
    test.genesis_state = from_json<TestState>(j.at("pre"));
    test.last_block_hash = from_json<hash256>(j.at("lastblockhash"));

    if (auto blocks = json::get_optional<json::value>(j, "blocks")) {
        for (const auto& block_json : *blocks) {
            if (block_json.contains("expectException"))
                continue;  // Skip invalid blocks
            test.blocks.push_back(from_json<Block>(block_json));
        }
    }

    return test;
}

std::vector<BlockchainTest> load_blockchain_tests(std::istream& input)
{
    std::vector<BlockchainTest> result;
    auto j = glz::read_json(input);

    for (const auto& [name, test_json] : j.items()) {
        auto test = from_json<BlockchainTest>(test_json);
        test.name = name;
        result.push_back(std::move(test));
    }

    return result;
}

}  // namespace evmone::test
