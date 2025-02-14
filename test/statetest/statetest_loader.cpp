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
namespace json = glz;
using evmc::from_hex;

namespace
{
template <typename T>
T load_if_exists(const json::value& j, std::string_view key)
{
    return json::get_optional<T>(j, key).value_or(T{});
}

template <typename T>
static std::optional<T> integer_from_json(const json::value& j)
{
    if (j.is_number())
        return j.get<T>();

    if (!j.is_string())
        return {};

    const auto s = j.get<std::string>();

    size_t num_processed = 0;
    const auto v = static_cast<T>(std::stoull(s, &num_processed, 0));
    if (num_processed == 0 || num_processed != s.size())
        return {};
    return v;
}

template <>
uint8_t from_json<uint8_t>(const json::value& j)
{
    const auto ret = std::stoul(j.get<std::string>(), nullptr, 16);
    if (ret > std::numeric_limits<uint8_t>::max())
        throw std::out_of_range("from_json<uint8_t>: value > 0xFF");

    return static_cast<uint8_t>(ret);
}

template <>
int64_t from_json<int64_t>(const json::value& j)
{
    const auto v = integer_from_json<int64_t>(j);
    if (!v.has_value())
        throw std::invalid_argument("from_json<int64_t>: must be integer or string of integer");
    return *v;
}

template <>
uint64_t from_json<uint64_t>(const json::value& j)
{
    const auto v = integer_from_json<uint64_t>(j);
    if (!v.has_value())
        throw std::invalid_argument("from_json<uint64_t>: must be integer or string of integer");
    return *v;
}

template <>
bytes from_json<bytes>(const json::value& j)
{
    return from_hex(j.get<std::string>()).value();
}

template <>
address from_json<address>(const json::value& j)
{
    return evmc::from_hex<address>(j.get<std::string>()).value();
}

template <>
hash256 from_json<hash256>(const json::value& j)
{
    const auto s = j.get<std::string>();
    if (s == "0" || s == "0x0")  // Special case to handle "0". Required by exec-spec-tests.
        return 0x00_bytes32;     // TODO: Get rid of it.

    const auto opt_hash = evmc::from_hex<hash256>(s);
    if (!opt_hash)
        throw std::invalid_argument("invalid hash: " + s);
    return *opt_hash;
}

template <>
intx::uint256 from_json<intx::uint256>(const json::value& j)
{
    const auto s = j.get<std::string>();
    if (s.starts_with("0x:bigint "))
        return std::numeric_limits<intx::uint256>::max();  // Fake it
    return intx::from_string<intx::uint256>(s);
}

template <>
state::AccessList from_json<state::AccessList>(const json::value& j)
{
    state::AccessList o;
    for (const auto& item : j.get<std::vector<json::value>>())
    {
        auto [addr, storage_keys] = glz::read<std::tuple<
            address,
            std::vector<bytes32>
        >>(item, {"address", "storageKeys"});
        
        o.emplace_back(addr, std::move(storage_keys));
    }
    return o;
}

template <>
state::AuthorizationList from_json<state::AuthorizationList>(const json::value& j)
{
    state::AuthorizationList o;
    for (const auto& item : j.get<std::vector<json::value>>())
    {
        auto [chain_id, addr, nonce, r, s, v] = glz::read<std::tuple<
            uint256,
            address,
            uint64_t,
            uint256,
            uint256,
            uint256
        >>(item, {"chainId", "address", "nonce", "r", "s", "v"});

        state::Authorization authorization{
            .chain_id = chain_id,
            .addr = addr,
            .nonce = nonce,
            .r = r,
            .s = s,
            .v = v
        };

        if (auto signer = json::get_optional<address>(item, "signer")) {
            authorization.signer = *signer;
        }

        o.emplace_back(authorization);
    }
    return o;
}

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

template <>
state::BlockInfo from_json_with_rev(const json::value& j, evmc_revision rev)
{
    // Use glaze's structured bindings for required fields
    auto [number, timestamp, gas_limit, coinbase] = glz::read<std::tuple<
        int64_t, int64_t, int64_t, evmc::address
    >>(j, {
        "currentNumber",
        "currentTimestamp",
        "currentGasLimit",
        "currentCoinbase"
    });

    // Handle optional fields
    auto parent_timestamp = json::get_optional<int64_t>(j, "parentTimestamp").value_or(0);
    auto parent_difficulty = json::get_optional<int64_t>(j, "parentDifficulty").value_or(0);
    auto parent_uncle_hash = json::get_optional<hash256>(j, "parentUncleHash").value_or(EmptyListHash);
    auto excess_blob_gas = json::get_optional<uint64_t>(j, "currentExcessBlobGas");

    // Handle difficulty/randao
    bytes32 prev_randao;
    int64_t current_difficulty;
    if (rev >= EVMC_PARIS) {
        prev_randao = json::at<bytes32>(j, "currentRandom");
        current_difficulty = 0;
    } else {
        current_difficulty = json::at<int64_t>(j, "currentDifficulty");
        prev_randao = intx::be::store<bytes32>(intx::uint256{current_difficulty});
    }

    // Handle base fee
    uint64_t base_fee = 0;
    if (rev >= EVMC_LONDON) {
        if (auto parent_base_fee = json::get_optional<uint64_t>(j, "parentBaseFee")) {
            base_fee = *parent_base_fee;
        } else {
            base_fee = json::at<uint64_t>(j, "currentBaseFee");
        }
    }

    // Handle withdrawals
    std::vector<state::Withdrawal> withdrawals;
    if (rev >= EVMC_SHANGHAI) {
        if (auto j_withdrawals = json::get_optional<json::value>(j, "withdrawals")) {
            withdrawals = glz::read<std::vector<state::Withdrawal>>(*j_withdrawals);
        }
    }

    // Handle ommers
    std::vector<state::Ommer> ommers;
    if (auto j_ommers = json::get_optional<json::value>(j, "ommers")) {
        ommers = glz::read<std::vector<state::Ommer>>(*j_ommers);
    }

    return state::BlockInfo{
        .number = number,
        .timestamp = timestamp,
        .parent_timestamp = parent_timestamp,
        .gas_limit = gas_limit,
        .coinbase = coinbase,
        .difficulty = current_difficulty,
        .parent_difficulty = parent_difficulty,
        .parent_ommers_hash = parent_uncle_hash,
        .prev_randao = prev_randao,
        .parent_beacon_block_root = json::get_optional<hash256>(j, "parentBeaconBlockRoot").value_or(hash256{}),
        .base_fee = base_fee,
        .blob_gas_used = json::get_optional<uint64_t>(j, "blobGasUsed").value_or(0),
        .excess_blob_gas = excess_blob_gas,
        .blob_base_fee = state::compute_blob_gas_price(rev, excess_blob_gas),
        .ommers = std::move(ommers),
        .withdrawals = std::move(withdrawals),
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

        if (auto storage = json::get_optional<json::value>(acc_json, "storage")) {
            for (const auto& [key, value] : storage->items()) {
                auto storage_value = json::get<bytes32>(value);
                if (!is_zero(storage_value)) {
                    acc.storage[json::get<bytes32>(key)] = storage_value;
                }
            }
        }
    }
    return state;
}

/// Load common parts of Transaction or TestMultiTransaction.
static void from_json_tx_common(const json::value& j, state::Transaction& o)
{
    // Handle gas price fields
    if (auto gas_price = json::get_optional<intx::uint256>(j, "gasPrice")) {
        o.type = state::Transaction::Type::legacy;
        o.max_gas_price = *gas_price;
        o.max_priority_gas_price = o.max_gas_price;
        
        // Check for invalid combination of fees
        if (j.contains("maxFeePerGas") || j.contains("maxPriorityFeePerGas")) {
            throw std::invalid_argument(
                "invalid transaction: contains both legacy and EIP-1559 fees");
        }
    } else {
        o.type = state::Transaction::Type::eip1559;
        auto [max_fee, max_priority_fee] = glz::read<std::tuple<intx::uint256, intx::uint256>>(
            j, {"maxFeePerGas", "maxPriorityFeePerGas"}
        );
        o.max_gas_price = max_fee;
        o.max_priority_gas_price = max_priority_fee;
    }

    // Handle optional fields
    if (auto max_blob_fee = json::get_optional<intx::uint256>(j, "maxFeePerBlobGas")) {
        o.max_blob_gas_price = *max_blob_fee;
    }

    // Handle blob hashes
    if (auto blob_hashes = json::get_optional<std::vector<bytes32>>(j, "blobVersionedHashes")) {
        o.type = state::Transaction::Type::blob;
        o.blob_hashes = *blob_hashes;
    }
    // Handle authorization list
    else if (auto auth_list = json::get_optional<state::AuthorizationList>(j, "authorizationList")) {
        o.type = state::Transaction::Type::set_code;
        o.authorization_list = *auth_list;
    }
}

template <>
state::Transaction from_json<state::Transaction>(const json::value& j)
{
    state::Transaction o;
    from_json_tx_common(j, o);

    // Use glaze's structured bindings for optional fields
    auto [data, gas_limit, value] = glz::read<std::tuple<
        std::optional<bytes>,
        std::optional<int64_t>,
        intx::uint256
    >>(j, {"data", "gasLimit", "value"});

    // Handle data/input field
    if (data) {
        o.data = *data;
    } else {
        o.data = json::at<bytes>(j, "input");
    }

    // Handle gas/gasLimit field
    if (gas_limit) {
        o.gas_limit = *gas_limit;
    } else {
        o.gas_limit = json::at<int64_t>(j, "gas");
    }

    o.value = value;

    if (auto access_list = json::get_optional<state::AccessList>(j, "accessList")) {
        o.access_list = *access_list;
        if (o.type == state::Transaction::Type::legacy)
            o.type = state::Transaction::Type::access_list;
    }

    if (auto type = json::get_optional<uint8_t>(j, "type")) {
        const auto inferred_type = stdx::to_underlying(o.type);
        if (*type != inferred_type)
            throw std::invalid_argument("wrong transaction type: " + std::to_string(*type) +
                                    ", expected: " + std::to_string(inferred_type));
    }

    auto [nonce, r, s, v] = glz::read<std::tuple<
        uint64_t,
        intx::uint256,
        intx::uint256,
        uint8_t
    >>(j, {"nonce", "r", "s", "v"});

    o.nonce = nonce;
    o.r = r;
    o.s = s;
    o.v = v;

    return o;
}

static void from_json(const json::value& j, TestMultiTransaction& o)
{
    from_json_tx_common(j, o);

    // Change array handling to use glaze
    auto [inputs, gas_limits, values] = glz::read<std::tuple<
        std::vector<bytes>,
        std::vector<int64_t>,
        std::vector<intx::uint256>
    >>(j, {"data", "gasLimit", "value"});

    o.inputs = std::move(inputs);
    o.gas_limits = std::move(gas_limits);
    o.values = std::move(values);

    if (auto access_lists = json::get_optional<std::vector<state::AccessList>>(j, "accessLists")) {
        o.access_lists = std::move(*access_lists);
        if (o.type == state::Transaction::Type::legacy)
            o.type = state::Transaction::Type::access_list;
    }
}

static void from_json(const json::value& j, TestMultiTransaction::Indexes& o) {
    auto [input, gas, value] = glz::read<std::tuple<size_t, size_t, size_t>>(
        j, {"data", "gas", "value"}
    );
    o.input = input;
    o.gas_limit = gas;
    o.value = value;
}

static void from_json(const json::value& j, StateTransitionTest::Case::Expectation& o) {
    auto [indexes, hash, logs] = glz::read<std::tuple<
        TestMultiTransaction::Indexes,
        hash256,
        hash256
    >>(j, {"indexes", "hash", "logs"});
    
    o.indexes = std::move(indexes);
    o.state_hash = hash;
    o.logs_hash = logs;
    o.exception = json::contains(j, "expectException");
}

static void from_json(const json::value& j_t, StateTransitionTest& o)
{
    // Use glaze's structured bindings
    auto [pre, transaction, env] = glz::read<std::tuple<
        TestState,
        TestMultiTransaction,
        TestBlockHashes
    >>(j_t, {"pre", "transaction", "env"});
    
    o.pre_state = std::move(pre);
    o.multi_tx = std::move(transaction);
    o.block_hashes = std::move(env);

    // Handle optional _info section
    if (auto info = json::get_optional<json::value>(j_t, "_info")) {
        if (auto labels = json::get_optional<json::value>(*info, "labels")) {
            for (const auto& [id, label] : labels->items()) {
                o.input_labels.emplace(
                    json::get<uint64_t>(id),
                    json::get<std::string>(label)
                );
            }
        }
    }

    for (const auto& [rev_name, expectations] : j_t.at("post").items())
    {
        // TODO(c++20): Use emplace_back with aggregate initialization.
        o.cases.push_back({to_rev(rev_name),
            expectations.get<std::vector<StateTransitionTest::Case::Expectation>>(),
            from_json_with_rev(j_t.at("env"), to_rev(rev_name))});
    }
}

static void from_json(const json::value& j, std::vector<StateTransitionTest>& o)
{
    for (const auto& [name, test] : j.items()) {
        auto t = glz::read<StateTransitionTest>(test);
        t.name = name;
        o.push_back(std::move(t));
    }
}

std::vector<StateTransitionTest> load_state_tests(std::istream& input) {
    return glz::read_json<std::vector<StateTransitionTest>>(input);
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
}

// Change JSON loading to use glaze
auto result = glz::read_json<StateTest>(input);
}  // namespace evmone::test
