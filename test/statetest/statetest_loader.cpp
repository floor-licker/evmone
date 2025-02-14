// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/stdx/utility.hpp"
#include "../utils/utils.hpp"
#include "../utils/glaze_meta.hpp"
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

}  // namespace evmone::test

std::vector<StateTransitionTest> load_state_tests(std::istream& input)
{
    const auto json = std::string{std::istreambuf_iterator<char>(input), {}};
    const auto j = glz::read_json<glz::json_t>(json).value();

    std::vector<StateTransitionTest> result;
    for (const auto& [name, test_json] : j.items())
    {
        auto test = glz::read<StateTransitionTest>(test_json);
        test.name = name;
        result.push_back(std::move(test));
    }
    return result;
}
