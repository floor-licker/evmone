// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include "eoftest.hpp"
#include <evmc/evmc.hpp>
#include <evmone/eof.hpp>
#include <glaze/glaze.hpp>

namespace evmone::test
{
namespace
{
struct EOFValidationTest
{
    struct Case
    {
        struct Expectation
        {
            evmc_revision rev = EVMC_OSAKA;
            bool result = false;
        };
        std::string name;
        evmc::bytes code;
        ContainerKind kind = ContainerKind::runtime;
        std::vector<Expectation> expectations;
    };
    std::string name;
    std::unordered_map<std::string, Case> cases;
};

} // anonymous namespace
} // namespace evmone::test

// Put all glaze meta definitions in the glz namespace
namespace glz {
    template <>
    struct meta<evmone::test::EOFValidationTest::Case::Expectation> {
        static constexpr auto value = object(
            "rev", &evmone::test::EOFValidationTest::Case::Expectation::rev,
            "result", &evmone::test::EOFValidationTest::Case::Expectation::result
        );
    };

    template <>
    struct meta<evmone::test::EOFValidationTest::Case> {
        static constexpr auto value = object(
            "name", &evmone::test::EOFValidationTest::Case::name,
            "code", &evmone::test::EOFValidationTest::Case::code,
            "containerKind", &evmone::test::EOFValidationTest::Case::kind,
            "expectations", &evmone::test::EOFValidationTest::Case::expectations
        );
    };

    template <>
    struct meta<evmone::test::EOFValidationTest> {
        static constexpr auto value = object(
            "name", &evmone::test::EOFValidationTest::name,
            "cases", &evmone::test::EOFValidationTest::cases
        );
    };
}

using evmone::ContainerKind;
using evmone::EOFValidationError;
using evmone::test::EOFValidationTest;

void from_json(const nlohmann::json& j, evmone::test::EOFValidationTest::Case& o)
{
    const auto code = evmc::from_hex(j.at("code").get<std::string>());
    if (!code)
        throw std::invalid_argument{"code is invalid hex string"};
    o.code = *code;

    if (j.contains("containerKind")) {
        if (j["containerKind"].get<std::string>() == "INITCODE")
            o.kind = ContainerKind::initcode;
    }

    for (const auto& [rev, result] : j.at("results").items()) {
        o.expectations.push_back({
            to_rev(rev), 
            result.at("result").get<bool>()
        });
    }
}

void from_json(const nlohmann::json& j, evmone::test::EOFValidationTest& o)
{
    if (!j.is_object() || j.empty())
        throw std::invalid_argument{"JSON test must be an object with single key of the test name"};

    for (const auto& [name, test] : j.at("vectors").items()) {
        o.cases.emplace(name, from_json<EOFValidationTest::Case>(test));
    }
}

void from_json(const nlohmann::json& j, std::vector<EOFValidationTest>& o)
{
    for (const auto& [name, test] : j.items()) {
        auto t = from_json<EOFValidationTest>(test);
        t.name = name;
        o.emplace_back(std::move(t));
    }
}

void run_eof_test(std::istream& input)
{
    const auto tests = glz::read_json<std::vector<EOFValidationTest>>(input);

    for (const auto& test : tests)
    {
        for (const auto& [name, test_case] : test.cases)
        {
            for (const auto& expectation : test_case.expectations)
            {
                const auto result = validate_eof(
                    expectation.rev, test_case.kind, test_case.code);
                const auto success = (result == EOFValidationError::success);

                if (success != expectation.result)
                {
                    throw std::runtime_error(
                        "unexpected validation result for " + test.name + "/" + name +
                        " at revision " + std::to_string(expectation.rev) +
                        ": expected " + std::to_string(expectation.result) +
                        ", got " + std::to_string(success));
                }
            }
        }
    }
}

} // namespace evmone::test

