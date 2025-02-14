// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../state/block.hpp"
#include "../state/errors.hpp"
#include "../state/test_state.hpp"
#include "../state/transaction.hpp"
#include <glaze/glaze.hpp>

namespace evmone::test
{

struct TestMultiTransaction : state::Transaction
{
    struct Indexes
    {
        size_t input = 0;
        size_t gas_limit = 0;
        size_t value = 0;
    };

    std::vector<state::AccessList> access_lists;
    std::vector<bytes> inputs;
    std::vector<int64_t> gas_limits;
    std::vector<intx::uint256> values;

    [[nodiscard]] Transaction get(const Indexes& indexes) const noexcept
    {
        Transaction tx{*this};
        if (!access_lists.empty())
            tx.access_list = access_lists.at(indexes.input);
        tx.data = inputs.at(indexes.input);
        tx.gas_limit = gas_limits.at(indexes.gas_limit);
        tx.value = values.at(indexes.value);
        return tx;
    }
};

// Add glaze meta info
template<>
struct glz::meta<TestMultiTransaction::Indexes> {
    static constexpr auto value = object(
        "input", &TestMultiTransaction::Indexes::input,
        "gas_limit", &TestMultiTransaction::Indexes::gas_limit,
        "value", &TestMultiTransaction::Indexes::value
    );
};

struct StateTransitionTest
{
    struct Case
    {
        struct Expectation
        {
            TestMultiTransaction::Indexes indexes;
            hash256 state_hash;
            hash256 logs_hash = EmptyListHash;
            bool exception = false;
        };

        evmc_revision rev;
        std::vector<Expectation> expectations;
        state::BlockInfo block;
    };

    std::string name;
    TestState pre_state;
    TestBlockHashes block_hashes;
    TestMultiTransaction multi_tx;
    std::vector<Case> cases;
    std::unordered_map<uint64_t, std::string> input_labels;
};

namespace glz {
    // Add meta definitions for basic types
    template <>
    struct meta<uint64_t> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (value.is_string()) {
                    self = std::stoull(value.get<std::string>(), nullptr, 0);
                } else {
                    self = value.get<uint64_t>();
                }
            }
        };
    };

    // Add meta definitions for all types
    template <>
    struct meta<StateTransitionTest> {
        static constexpr auto value = object(
            "name", &StateTransitionTest::name,
            "pre_state", &StateTransitionTest::pre_state,
            "block_hashes", &StateTransitionTest::block_hashes,
            "multi_tx", &StateTransitionTest::multi_tx,
            "cases", &StateTransitionTest::cases,
            "input_labels", &StateTransitionTest::input_labels
        );
    };

    template <>
    struct meta<StateTransitionTest::Case> {
        static constexpr auto value = object(
            "rev", &StateTransitionTest::Case::rev,
            "expectations", &StateTransitionTest::Case::expectations,
            "block", &StateTransitionTest::Case::block
        );
    };

    // Add meta for Case::Expectation
    template <>
    struct meta<StateTransitionTest::Case::Expectation> {
        static constexpr auto value = object(
            "indexes", &StateTransitionTest::Case::Expectation::indexes,
            "hash", &StateTransitionTest::Case::Expectation::state_hash,
            "logs", &StateTransitionTest::Case::Expectation::logs_hash,
            "expectException", &StateTransitionTest::Case::Expectation::exception
        );
    };

    // Add meta for TestMultiTransaction
    template <>
    struct meta<TestMultiTransaction> {
        static constexpr auto value = object(
            "accessLists", &TestMultiTransaction::access_lists,
            "data", &TestMultiTransaction::inputs,
            "gasLimit", &TestMultiTransaction::gas_limits,
            "value", &TestMultiTransaction::values,
            "nonce", &TestMultiTransaction::nonce,
            "maxFeePerGas", &TestMultiTransaction::max_gas_price,
            "maxPriorityFeePerGas", &TestMultiTransaction::max_priority_gas_price,
            "type", &TestMultiTransaction::type,
            "blobVersionedHashes", &TestMultiTransaction::blob_hashes,
            "maxFeePerBlobGas", &TestMultiTransaction::max_blob_gas_price,
            "authorizationList", &TestMultiTransaction::authorization_list,
            "r", &TestMultiTransaction::r,
            "s", &TestMultiTransaction::s,
            "v", &TestMultiTransaction::v
        );
    };

    // Add meta for bytes (hex string conversion)
    template <>
    struct meta<bytes> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto hex = value.template get<std::string>();
                self = evmc::from_hex(hex).value();
            } else {
                value = "0x" + evmc::hex(self);
            }
        };
    };

    // Add meta for hash256 (hex string conversion)
    template <>
    struct meta<hash256> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto hex = value.template get<std::string>();
                if (hex == "0" || hex == "0x0") {
                    self = 0x00_bytes32;
                    return;
                }
                self = evmc::from_hex<hash256>(hex).value();
            } else {
                value = "0x" + evmc::hex(self);
            }
        };
    };
}

/// Returns the standardized error message for the transaction validation error.
[[nodiscard]] std::string get_invalid_tx_message(state::ErrorCode errc) noexcept;


std::vector<StateTransitionTest> load_state_tests(std::istream& input);

/// Validates an Ethereum state:
/// - checks that there are no zero-value storage entries,
/// - checks that there are no invalid EOF codes.
/// Throws std::invalid_argument exception.
void validate_state(const TestState& state, evmc_revision rev);

/// Execute the state @p test using the @p vm.
///
/// @param trace_summary  Output execution summary to the default trace stream.
void run_state_test(const StateTransitionTest& test, evmc::VM& vm, bool trace_summary);

/// Computes the hash of the RLP-encoded list of transaction logs.
/// This method is only used in tests.
hash256 logs_hash(const std::vector<state::Log>& logs);

/// Converts an integer to hex string representation with 0x prefix.
///
/// This handles also builtin types like uint64_t. Not optimal but works for now.
inline std::string hex0x(const intx::uint256& v)
{
    return "0x" + intx::hex(v);
}

/// Encodes bytes as hex with 0x prefix.
inline std::string hex0x(const bytes_view& v)
{
    return "0x" + evmc::hex(v);
}
}  // namespace evmone::test

inline std::ostream& operator<<(std::ostream& out, const evmone::address& a)
{
    return out << evmone::test::hex0x(a);
}

inline std::ostream& operator<<(std::ostream& out, const evmone::bytes32& b)
{
    return out << evmone::test::hex0x(b);
}
