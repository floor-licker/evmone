// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/stdx/utility.hpp"
#include "../utils/utils.hpp"
#include "statetest.hpp"
#include <evmone/eof.hpp>
#include <glaze/glaze.hpp>

namespace evmone::test
{
using evmc::from_hex;

namespace
{
// Based on calculateEIP1559BaseFee from ethereum/retesteth
static uint64_t calculate_current_base_fee_eip1559(
    uint64_t parent_gas_used, uint64_t parent_gas_limit, uint64_t parent_base_fee)
{
    // TODO: Make sure that 64-bit precision is good enough.
    static constexpr auto BASE_FEE_MAX_CHANGE_DENOMINATOR = 8;
    static constexpr auto ELASTICITY_MULTIPLIER = 2;

    uint64_t base_fee = 0;

    const auto parent_gas_target = parent_gas_limit / ELASTICITY_MULTIPLIER;

    if (parent_gas_used == parent_gas_target)
        base_fee = parent_base_fee;
    else if (parent_gas_used > parent_gas_target)
    {
        const auto gas_used_delta = parent_gas_used - parent_gas_target;
        const auto formula =
            parent_base_fee * gas_used_delta / parent_gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR;
        const auto base_fee_per_gas_delta = formula > 1 ? formula : 1;
        base_fee = parent_base_fee + base_fee_per_gas_delta;
    }
    else
    {
        const auto gas_used_delta = parent_gas_target - parent_gas_used;

        const auto base_fee_per_gas_delta_u128 =
            intx::uint128(parent_base_fee, 0) * intx::uint128(gas_used_delta, 0) /
            parent_gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR;

        const auto base_fee_per_gas_delta = base_fee_per_gas_delta_u128[0];
        if (parent_base_fee > base_fee_per_gas_delta)
            base_fee = parent_base_fee - base_fee_per_gas_delta;
        else
            base_fee = 0;
    }
    return base_fee;
}

template <>
state::Withdrawal from_json<state::Withdrawal>(const json::value& j)
{
    auto [index, validator_index, addr, amount] = glz::read<std::tuple<
        uint64_t, uint64_t, evmc::address, uint64_t
    >>(j, {"index", "validatorIndex", "address", "amount"});

    return {index, validator_index, addr, amount};
}

namespace glz {
    template <>
    struct meta<state::BlockInfoWithRev> {
        static constexpr auto value = [](auto&& self, auto&& value, evmc_revision rev) {
            if constexpr (glz::is_reading) {
                // Read required fields
                auto [number, timestamp, gas_limit, coinbase] = glz::read<std::tuple<
                    int64_t, int64_t, int64_t, evmc::address
                >>(value, {
                    "currentNumber",
                    "currentTimestamp",
                    "currentGasLimit",
                    "currentCoinbase"
                });

                // Handle optional fields with glaze
                auto parent_timestamp = glz::get_value<int64_t>(value, "parentTimestamp").value_or(0);
                auto parent_difficulty = glz::get_value<int64_t>(value, "parentDifficulty").value_or(0);
                auto parent_uncle_hash = glz::get_value<hash256>(value, "parentUncleHash").value_or(EmptyListHash);
                auto excess_blob_gas = glz::get_value<uint64_t>(value, "currentExcessBlobGas");

                // Handle difficulty/randao
                bytes32 prev_randao;
                int64_t current_difficulty;
                if (rev >= EVMC_PARIS) {
                    prev_randao = glz::read<bytes32>(value, "currentRandom");
                    current_difficulty = 0;
                } else {
                    current_difficulty = glz::read<int64_t>(value, "currentDifficulty");
                    prev_randao = intx::be::store<bytes32>(intx::uint256{current_difficulty});
                }

                // Handle base fee
                uint64_t base_fee = 0;
                if (rev >= EVMC_LONDON) {
                    if (auto parent_base_fee = glz::get_value<uint64_t>(value, "parentBaseFee")) {
                        base_fee = *parent_base_fee;
                    } else {
                        base_fee = glz::read<uint64_t>(value, "currentBaseFee");
                    }
                }

                // Handle withdrawals
                std::vector<state::Withdrawal> withdrawals;
                if (rev >= EVMC_SHANGHAI) {
                    if (auto withdrawals_opt = glz::get_value<std::vector<state::Withdrawal>>(value, "withdrawals")) {
                        withdrawals = *withdrawals_opt;
                    }
                }

                // Handle ommers
                std::vector<state::Ommer> ommers;
                if (auto ommers_opt = glz::get_value<std::vector<state::Ommer>>(value, "ommers")) {
                    ommers = std::move(*ommers_opt);
                }

                self = state::BlockInfo{
                    .number = number,
                    .timestamp = timestamp,
                    .parent_timestamp = parent_timestamp,
                    .gas_limit = gas_limit,
                    .coinbase = coinbase,
                    .difficulty = current_difficulty,
                    .parent_difficulty = parent_difficulty,
                    .parent_ommers_hash = parent_uncle_hash,
                    .prev_randao = prev_randao,
                    .parent_beacon_block_root = glz::get_value<hash256>(value, "parentBeaconBlockRoot").value_or(hash256{}),
                    .base_fee = base_fee,
                    .blob_gas_used = glz::get_value<uint64_t>(value, "blobGasUsed").value_or(0),
                    .excess_blob_gas = excess_blob_gas,
                    .blob_base_fee = state::compute_blob_gas_price(rev, excess_blob_gas),
                    .ommers = std::move(ommers),
                    .withdrawals = std::move(withdrawals),
                };
            }
        };
    };
}

template <>
TestBlockHashes from_json<TestBlockHashes>(const json::value& j)
{
    TestBlockHashes block_hashes;
    if (auto block_hashes_it = json::get_optional<json::value>(j, "blockHashes")) {
        for (const auto& [num, hash] : block_hashes_it->items()) {
            block_hashes[json::get<int64_t>(num)] = json::get<hash256>(hash);
        }
    }
    return block_hashes;
}

template <>
TestState from_json<TestState>(const json::value& j)
{
    TestState state;
    for (const auto& [addr_str, acc_json] : j.items()) {
        auto addr = json::get<address>(addr_str);
        auto [nonce, balance, code] = glz::read<std::tuple<
            uint64_t, intx::uint256, bytes
        >>(acc_json, {"nonce", "balance", "code"});

        auto& acc = state[addr];
        acc.nonce = nonce;
        acc.balance = balance;
        acc.code = code;

        if (auto storage_opt = glz::get_value<std::map<bytes32, bytes32>>(acc_json, "storage")) {
            acc.storage = std::move(*storage_opt);
        }
    }
    return state;
}

namespace glz {
    // Add meta for Transaction
    template <>
    struct meta<state::Transaction> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                // First read common fields
                meta<state::TransactionCommon>::value(self, value);

                // Handle data/input field
                if (auto data = glz::get_value<bytes>(value, "data")) {
                    self.data = *data;
                } else {
                    self.data = glz::read<bytes>(value, "input");
                }

                // Handle gas/gasLimit field
                if (auto gas_limit = glz::get_value<int64_t>(value, "gasLimit")) {
                    self.gas_limit = *gas_limit;
                } else {
                    self.gas_limit = glz::read<int64_t>(value, "gas");
                }
            }
        };
    };

    // Add meta for TestBlockHashes
    template <>
    struct meta<TestBlockHashes> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (auto block_hashes = glz::get_value<glz::json_t>(value, "blockHashes")) {
                    for (const auto& [num, hash] : block_hashes->items()) {
                        self[std::stoll(num)] = glz::read<hash256>(hash);
                    }
                }
            }
        };
    };
}

void validate_state(const TestState& state, evmc_revision rev)
{
    for (const auto& [addr, acc] : state)
    {
        // TODO: Check for empty accounts after Paris.
        //       https://github.com/ethereum/tests/issues/1331
        if (is_eof_container(acc.code))
        {
            if (rev >= EVMC_OSAKA)
            {
                if (const auto result = validate_eof(rev, ContainerKind::runtime, acc.code);
                    result != EOFValidationError::success)
                {
                    throw std::invalid_argument(
                        "EOF container at " + hex0x(addr) +
                        " is invalid: " + std::string(get_error_message(result)));
                }
            }
            else
            {
                throw std::invalid_argument("unexpected code with EOF prefix at " + hex0x(addr));
            }
        }

        for (const auto& [key, value] : acc.storage)
        {
            if (is_zero(value))
            {
                throw std::invalid_argument{"account " + hex0x(addr) +
                                            " contains invalid zero-value storage entry " +
                                            hex0x(key)};
            }
        }
    }
}

// Add meta definitions for any remaining types
template<>
struct glz::meta<state::AuthorizationList> {
    static constexpr auto value = object(
        "chain_id", &state::AuthorizationList::chain_id,
        "signer", &state::AuthorizationList::signer,
        "nonce", &state::AuthorizationList::nonce,
        "code_hash", &state::AuthorizationList::code_hash,
        "r", &state::AuthorizationList::r,
        "s", &state::AuthorizationList::s,
        "v", &state::AuthorizationList::v
    );
};

// Add glaze meta definitions for the types
namespace glz {
    template <>
    struct meta<StateTestLoader> {
        static constexpr auto value = object(
            // Add fields here
        );
    };

    template <>
    struct meta<state::Transaction> {
        static constexpr auto value = object(
            "data", &state::Transaction::data,
            "gasLimit", &state::Transaction::gas_limit,
            "value", &state::Transaction::value,
            "nonce", &state::Transaction::nonce,
            "maxFeePerGas", &state::Transaction::max_gas_price,
            "maxPriorityFeePerGas", &state::Transaction::max_priority_gas_price,
            "type", &state::Transaction::type,
            "accessList", &state::Transaction::access_list,
            "blobVersionedHashes", &state::Transaction::blob_hashes,
            "maxFeePerBlobGas", &state::Transaction::max_blob_gas_price,
            "authorizationList", &state::Transaction::authorization_list,
            "r", &state::Transaction::r,
            "s", &state::Transaction::s,
            "v", &state::Transaction::v
        );
    };
    
    template <>
    struct meta<TestMultiTransaction> {
        static constexpr auto value = object(
            "data", &TestMultiTransaction::inputs,
            "gasLimit", &TestMultiTransaction::gas_limits,
            "value", &TestMultiTransaction::values,
            "accessLists", &TestMultiTransaction::access_lists,
            "maxFeePerGas", &TestMultiTransaction::max_gas_price,
            "maxPriorityFeePerGas", &TestMultiTransaction::max_priority_gas_price,
            "type", &TestMultiTransaction::type
        );
    };

    // Add other meta definitions for:
    // - StateTransitionTest
    // - StateTransitionTest::Case
    // - StateTransitionTest::Case::Expectation
    // - TestBlockHashes
    // - TestState
    // etc.

    template <>
    struct meta<StateTransitionTest> {
        static constexpr auto value = object(
            "name", &StateTransitionTest::name,
            "pre_state", &StateTransitionTest::pre_state,
            "multi_tx", &StateTransitionTest::multi_tx,
            "block_hashes", &StateTransitionTest::block_hashes,
            "input_labels", &StateTransitionTest::input_labels,
            "cases", &StateTransitionTest::cases
        );
    };

    template <>
    struct meta<StateTransitionTest::Case> {
        static constexpr auto value = object(
            "revision", &StateTransitionTest::Case::revision,
            "expectations", &StateTransitionTest::Case::expectations,
            "block_info", &StateTransitionTest::Case::block_info
        );
    };

    template <>
    struct meta<StateTransitionTest::Case::Expectation> {
        static constexpr auto value = object(
            "indexes", &StateTransitionTest::Case::Expectation::indexes,
            "state_hash", &StateTransitionTest::Case::Expectation::state_hash,
            "logs_hash", &StateTransitionTest::Case::Expectation::logs_hash,
            "exception", &StateTransitionTest::Case::Expectation::exception
        );
    };

    template <>
    struct meta<TestMultiTransaction::Indexes> {
        static constexpr auto value = object(
            "data", &TestMultiTransaction::Indexes::input,
            "gas", &TestMultiTransaction::Indexes::gas_limit,
            "value", &TestMultiTransaction::Indexes::value
        );
    };

    template <>
    struct meta<state::BlockInfo> {
        static constexpr auto value = object(
            "number", &state::BlockInfo::number,
            "timestamp", &state::BlockInfo::timestamp,
            "gas_limit", &state::BlockInfo::gas_limit,
            "coinbase", &state::BlockInfo::coinbase,
            "difficulty", &state::BlockInfo::difficulty,
            "base_fee", &state::BlockInfo::base_fee,
            "prev_randao", &state::BlockInfo::prev_randao,
            "parent_timestamp", &state::BlockInfo::parent_timestamp,
            "parent_difficulty", &state::BlockInfo::parent_difficulty,
            "parent_ommers_hash", &state::BlockInfo::parent_ommers_hash,
            "excess_blob_gas", &state::BlockInfo::excess_blob_gas,
            "withdrawals", &state::BlockInfo::withdrawals,
            "ommers", &state::BlockInfo::ommers
        );
    };

    // For hex string to uint8_t conversion
    template <>
    struct meta<uint8_t> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto hex = value.template get<std::string>();
                const auto ret = std::stoul(hex, nullptr, 16);
                if (ret > std::numeric_limits<uint8_t>::max())
                    throw std::out_of_range("value > 0xFF");
                self = static_cast<uint8_t>(ret);
            }
        };
    };

    // For hex string to bytes conversion
    template <>
    struct meta<bytes> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                self = from_hex(value.template get<std::string>()).value();
            }
        };
    };

    // For hex string to address conversion
    template <>
    struct meta<address> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                self = evmc::from_hex<address>(value.template get<std::string>()).value();
            }
        };
    };

    // For hash256 conversion
    template <>
    struct meta<hash256> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto s = value.template get<std::string>();
                if (s == "0" || s == "0x0") {
                    self = 0x00_bytes32;
                    return;
                }
                const auto opt_hash = evmc::from_hex<hash256>(s);
                if (!opt_hash)
                    throw std::invalid_argument("invalid hash: " + s);
                self = *opt_hash;
            }
        };
    };

    // For uint256 conversion
    template <>
    struct meta<intx::uint256> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto s = value.template get<std::string>();
                if (s.starts_with("0x:bigint "))
                    self = std::numeric_limits<intx::uint256>::max();  // Fake it
                else
                    self = intx::from_string<intx::uint256>(s);
            }
        };
    };

    // Update TestState meta to handle the full deserialization
    template <>
    struct meta<TestState> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                for (const auto& [addr_str, acc_json] : value.items()) {
                    auto addr = glz::read<address>(addr_str);
                    auto [nonce, balance, code] = glz::read<std::tuple<
                        uint64_t, intx::uint256, bytes
                    >>(acc_json, {"nonce", "balance", "code"});

                    auto& acc = self[addr];
                    acc.nonce = nonce;
                    acc.balance = balance;
                    acc.code = code;

                    if (auto storage_opt = glz::get_value<std::map<bytes32, bytes32>>(acc_json, "storage")) {
                        acc.storage = std::move(*storage_opt);
                    }
                }
            }
        };
    };

    // Add meta for state::AccessList
    template <>
    struct meta<state::AccessList> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                for (const auto& item : value) {
                    auto [addr, storage_keys] = glz::read<std::tuple<
                        address,
                        std::vector<bytes32>
                    >>(item, {"address", "storageKeys"});
                    self.emplace_back(addr, std::move(storage_keys));
                }
            }
        };
    };

    // Add meta for integer types
    template <>
    struct meta<int64_t> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (value.is_string()) {
                    const auto s = value.template get<std::string>();
                    self = std::stoll(s, nullptr, 0);
                } else {
                    self = value.template get<int64_t>();
                }
            }
        };
    };

    template <>
    struct meta<uint64_t> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (value.is_string()) {
                    const auto s = value.template get<std::string>();
                    self = std::stoull(s, nullptr, 0);
                } else {
                    self = value.template get<uint64_t>();
                }
            }
        };
    };

    // Add meta for AuthorizationList
    template <>
    struct meta<state::AuthorizationList> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                for (const auto& item : value) {
                    auto [chain_id, addr, nonce, r, s, v] = glz::read<std::tuple<
                        uint256,
                        address,
                        uint64_t,
                        uint256,
                        uint256,
                        uint256
                    >>(item, {"chainId", "address", "nonce", "r", "s", "v"});

                    state::Authorization auth{
                        .chain_id = chain_id,
                        .addr = addr,
                        .nonce = nonce,
                        .r = r,
                        .s = s,
                        .v = v
                    };

                    if (auto signer = glz::get_value<address>(item, "signer")) {
                        auth.signer = *signer;
                    }

                    self.emplace_back(std::move(auth));
                }
            }
        };
    };

    // Add meta for Withdrawal
    template <>
    struct meta<state::Withdrawal> {
        static constexpr auto value = object(
            "index", &state::Withdrawal::index,
            "validatorIndex", &state::Withdrawal::validator_index,
            "address", &state::Withdrawal::recipient,
            "amount", &state::Withdrawal::amount
        );
    };
}
}  // namespace evmone::test
