// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "state_view.hpp"
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <map>
#include <span>
#include <variant>
#include <glaze/glaze.hpp>
#include "../utils/glaze_meta.hpp"

namespace evmone
{
namespace state
{
struct BlockInfo;
struct Ommer;
struct Requests;
struct StateDiff;
struct Transaction;
struct TransactionReceipt;
struct Withdrawal;
struct AccessList;
struct Log;
struct TransactionTrace;
}  // namespace state

namespace test
{
using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using intx::uint256;

/// Ethereum account representation for tests.
struct TestAccount
{
    uint64_t nonce = 0;
    uint256 balance;
    std::map<bytes32, bytes32> storage;
    bytes code;

    bool operator==(const TestAccount&) const noexcept = default;
};

/// Ethereum State representation for tests.
///
/// This is a simplified variant of state::State:
/// it hides some details related to transaction execution (e.g. original storage values)
/// and is also easier to work with in tests.
class TestState : public state::StateView, public std::map<address, TestAccount>
{
public:
    using map::map;

    std::optional<Account> get_account(const address& addr) const noexcept override;
    bytes get_account_code(const address& addr) const noexcept override;
    bytes32 get_storage(const address& addr, const bytes32& key) const noexcept override;

    /// Inserts new account to the state.
    ///
    /// This method is for compatibility with state::State::insert().
    /// Don't use it in new tests, use std::map interface instead.
    /// TODO: deprecate this method.
    void insert(const address& addr, TestAccount&& acc) { (*this)[addr] = std::move(acc); }

    /// Gets the reference to an existing account.
    ///
    /// This method is for compatibility with state::State::get().
    /// Don't use it in new tests, use std::map interface instead.
    /// TODO: deprecate this method.
    TestAccount& get(const address& addr) { return (*this)[addr]; }

    /// Apply the state changes.
    void apply(const state::StateDiff& diff);
};

class TestBlockHashes : public state::BlockHashes, public std::unordered_map<int64_t, bytes32>
{
public:
    using std::unordered_map<int64_t, bytes32>::unordered_map;

    bytes32 get_block_hash(int64_t block_number) const noexcept override;
};

/// Wrapping of state::transition() which operates on TestState.
[[nodiscard]] std::variant<state::TransactionReceipt, std::error_code> transition(TestState& state,
    const state::BlockInfo& block, const state::BlockHashes& block_hashes,
    const state::Transaction& tx, evmc_revision rev, evmc::VM& vm, int64_t block_gas_left,
    int64_t blob_gas_left);

/// Wrapping of state::finalize() which operates on TestState.
void finalize(TestState& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const state::Ommer> ommers,
    std::span<const state::Withdrawal> withdrawals);

/// Wrapping of state::system_call_block_start() which operates on TestState.
void system_call_block_start(TestState& state, const state::BlockInfo& block,
    const state::BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm);

/// Wrapping of state::system_call_block_end() which operates on TestState.
std::vector<state::Requests> system_call_block_end(TestState& state, const state::BlockInfo& block,
    const state::BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm);

namespace glz {
    // Add meta for TestAccount
    template <>
    struct meta<TestAccount> {
        static constexpr auto value = object(
            "nonce", &TestAccount::nonce,
            "balance", &TestAccount::balance,
            "storage", &TestAccount::storage,
            "code", &TestAccount::code
        );
    };

    // Add meta for TestState
    template <>
    struct meta<TestState> {
        static constexpr auto value = object(
            "accounts", &TestState::accounts
        );
    };

    // Add meta for state::Transaction
    template <>
    struct meta<state::Transaction> {
        static constexpr auto value = object(
            "nonce", &state::Transaction::nonce,
            "gasPrice", &state::Transaction::max_gas_price,
            "maxFeePerGas", &state::Transaction::max_gas_price,
            "maxPriorityFeePerGas", &state::Transaction::max_priority_gas_price,
            "gas", &state::Transaction::gas_limit,
            "to", &state::Transaction::to,
            "value", &state::Transaction::value,
            "data", &state::Transaction::data,
            "accessList", &state::Transaction::access_list,
            "type", &state::Transaction::type,
            "chainId", &state::Transaction::chain_id,
            "v", &state::Transaction::v,
            "r", &state::Transaction::r,
            "s", &state::Transaction::s
        );
    };

    // Add meta for state::BlockHashes
    template <>
    struct meta<state::BlockHashes> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (auto block_hashes = glz::get_value<std::map<int64_t, bytes32>>(value, "blockHashes")) {
                    for (const auto& [num, hash] : *block_hashes) {
                        self[num] = hash;
                    }
                }
            }
        };
    };

    // Add meta for state::StateDiff
    template <>
    struct meta<state::StateDiff> {
        static constexpr auto value = object(
            "accounts", &state::StateDiff::accounts,
            "storage", &state::StateDiff::storage
        );
    };

    // Add meta for state::AccessList
    template <>
    struct meta<state::AccessList> {
        static constexpr auto value = object(
            "address", &state::AccessList::address,
            "storageKeys", &state::AccessList::storage_keys
        );
    };

    // Add meta for state::Ommer
    template <>
    struct meta<state::Ommer> {
        static constexpr auto value = object(
            "address", &state::Ommer::address,
            "delta", &state::Ommer::delta
        );
    };

    // Add meta for state::Authorization
    template <>
    struct meta<state::Authorization> {
        static constexpr auto value = object(
            "chain_id", &state::Authorization::chain_id,
            "addr", &state::Authorization::addr,
            "nonce", &state::Authorization::nonce,
            "signer", &state::Authorization::signer,
            "r", &state::Authorization::r,
            "s", &state::Authorization::s,
            "v", &state::Authorization::v
        );
    };

    // Add meta for TestBlockHashes
    template <>
    struct meta<TestBlockHashes> {
        static constexpr auto value = object(
            "blockHashes", &TestBlockHashes::operator std::unordered_map<int64_t, bytes32>&
        );
    };

    // Add meta for state::TransactionTrace
    template <>
    struct meta<state::TransactionTrace> {
        static constexpr auto value = object(
            "pc", &state::TransactionTrace::pc,
            "op", &state::TransactionTrace::op,
            "gas", &state::TransactionTrace::gas,
            "gasCost", &state::TransactionTrace::gas_cost,
            "memory", &state::TransactionTrace::memory,
            "stack", &state::TransactionTrace::stack,
            "depth", &state::TransactionTrace::depth,
            "refund", &state::TransactionTrace::refund,
            "error", &state::TransactionTrace::error,
            "reverted", &state::TransactionTrace::reverted
        );
    };
}
}  // namespace test
}  // namespace evmone
