// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../statetest/statetest.hpp"
#include "../utils/utils.hpp"
#include "blockchaintest.hpp"
#include "../utils/glaze_meta.hpp"

namespace evmone::test
{

namespace
{
template <typename T>
std::optional<T> load_optional(const glz::json_t& j, std::string_view key)
{
    return glz::get_value<T>(j, key);
}
}  // namespace

BlockchainTest load_blockchain_test(std::istream& input)
{
    const auto json = std::string{std::istreambuf_iterator<char>(input), {}};
    const auto j = glz::read_json<glz::json_t>(json).value();
    auto test = from_json<BlockchainTest>(j);
    test.name = j.at("name").get<std::string>();
    return test;
}

namespace glz {
    template <>
    struct meta<BlockHeader> {
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

    template <>
    struct meta<Block> {
        static constexpr auto value = object(
            "blockHeader", &Block::header,
            "transactions", &Block::transactions,
            "uncleHeaders", &Block::ommers,
            "withdrawals", &Block::withdrawals
        );
    };
}

}  // namespace evmone::test
