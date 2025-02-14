// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../state/block.hpp"
#include "../state/bloom_filter.hpp"
#include "../state/test_state.hpp"
#include "../state/transaction.hpp"
#include "../utils/utils.hpp"
#include <evmc/evmc.hpp>
#include <span>
#include <vector>
#include <glaze/glaze.hpp>

namespace evmone::test
{
struct UnsupportedTestFeature : std::runtime_error
{
    using runtime_error::runtime_error;
};

// https://ethereum.org/en/developers/docs/blocks/
struct BlockHeader
{
    hash256 parent_hash;
    address coinbase;
    hash256 state_root;
    hash256 receipts_root;
    state::BloomFilter logs_bloom;
    int64_t difficulty;
    bytes32 prev_randao;
    int64_t block_number;
    int64_t gas_limit;
    int64_t gas_used;
    int64_t timestamp;
    bytes extra_data;
    uint64_t base_fee_per_gas;
    hash256 hash;
    hash256 transactions_root;
    hash256 withdrawal_root;
    hash256 parent_beacon_block_root;
    std::optional<uint64_t> blob_gas_used;
    std::optional<uint64_t> excess_blob_gas;
    hash256 requests_hash;
};

struct TestBlock
{
    state::BlockInfo block_info;
    std::vector<state::Transaction> transactions;
    bool valid = true;

    BlockHeader expected_block_header;
};

struct BlockchainTest
{
    struct Expectation
    {
        hash256 last_block_hash;
        std::variant<TestState, hash256> post_state;
    };

    std::string name;

    std::vector<TestBlock> test_blocks;
    BlockHeader genesis_block_header;
    TestState pre_state;
    RevisionSchedule rev;

    Expectation expectation;
};

template<>
struct glz::meta<BlockHeader> {
    static constexpr auto value = object(
        "parentHash", &BlockHeader::parent_hash,
        "coinbase", &BlockHeader::coinbase,
        "stateRoot", &BlockHeader::state_root,
        "receiptTrie", &BlockHeader::receipts_root,
        "bloom", &BlockHeader::logs_bloom,
        "difficulty", &BlockHeader::difficulty,
        "mixHash", &BlockHeader::prev_randao,
        "number", &BlockHeader::block_number,
        "gasLimit", &BlockHeader::gas_limit,
        "gasUsed", &BlockHeader::gas_used,
        "timestamp", &BlockHeader::timestamp,
        "extraData", &BlockHeader::extra_data,
        "baseFeePerGas", &BlockHeader::base_fee_per_gas,
        "hash", &BlockHeader::hash,
        "transactionsTrie", &BlockHeader::transactions_root,
        "withdrawalsRoot", &BlockHeader::withdrawal_root,
        "parentBeaconBlockRoot", &BlockHeader::parent_beacon_block_root,
        "blobGasUsed", &BlockHeader::blob_gas_used
    );
};

template<>
struct glz::meta<Block> {
    static constexpr auto value = object(
        "blockHeader", &Block::header,
        "transactions", &Block::transactions,
        "uncleHeaders", &Block::ommers,
        "withdrawals", &Block::withdrawals
    );
};

template<>
struct glz::meta<BlockchainTest> {
    static constexpr auto value = object(
        "network", &BlockchainTest::rev,
        "genesisBlockHeader", &BlockchainTest::genesis_header,
        "pre", &BlockchainTest::genesis_state,
        "lastblockhash", &BlockchainTest::last_block_hash,
        "blocks", &BlockchainTest::blocks
    );
};

std::vector<BlockchainTest> load_blockchain_tests(std::istream& input);

void run_blockchain_tests(std::span<const BlockchainTest> tests, evmc::VM& vm);

}  // namespace evmone::test
