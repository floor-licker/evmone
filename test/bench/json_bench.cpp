#include <benchmark/benchmark.h>
#include <glaze/glaze.hpp>
#include "../utils/glaze_meta.hpp"

struct StateTransitionTest {
    struct Env {
        std::string currentCoinbase;
        std::string currentDifficulty;
        std::string currentGasLimit;
        std::string currentNumber;
        std::string currentTimestamp;
        std::string currentBaseFee;
        std::map<std::string, std::string> blockHashes;
    };

    struct Account {
        std::string nonce;
        std::string balance;
        std::string code;
        std::map<std::string, std::string> storage;
    };

    struct Transaction {
        std::vector<std::string> data;
        std::vector<std::string> gasLimit;
        std::vector<std::string> value;
    };

    Env env;
    std::map<std::string, Account> pre;
    Transaction transaction;
};

namespace glz {
    template <>
    struct meta<StateTransitionTest::Env> {
        static constexpr auto value = object(
            "currentCoinbase", &StateTransitionTest::Env::currentCoinbase,
            "currentDifficulty", &StateTransitionTest::Env::currentDifficulty,
            "currentGasLimit", &StateTransitionTest::Env::currentGasLimit,
            "currentNumber", &StateTransitionTest::Env::currentNumber,
            "currentTimestamp", &StateTransitionTest::Env::currentTimestamp,
            "currentBaseFee", &StateTransitionTest::Env::currentBaseFee,
            "blockHashes", &StateTransitionTest::Env::blockHashes
        );
    };

    template <>
    struct meta<StateTransitionTest::Account> {
        static constexpr auto value = object(
            "nonce", &StateTransitionTest::Account::nonce,
            "balance", &StateTransitionTest::Account::balance,
            "code", &StateTransitionTest::Account::code,
            "storage", &StateTransitionTest::Account::storage
        );
    };

    template <>
    struct meta<StateTransitionTest::Transaction> {
        static constexpr auto value = object(
            "data", &StateTransitionTest::Transaction::data,
            "gasLimit", &StateTransitionTest::Transaction::gasLimit,
            "value", &StateTransitionTest::Transaction::value
        );
    };

    template <>
    struct meta<StateTransitionTest> {
        static constexpr auto value = object(
            "env", &StateTransitionTest::env,
            "pre", &StateTransitionTest::pre,
            "transaction", &StateTransitionTest::transaction
        );
    };
}

static const std::string large_json = R"({
    "env": {
        "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
        "currentDifficulty": "0x20000",
        "currentGasLimit": "0xff112233445566",
        "currentNumber": "1",
        "currentTimestamp": "1000",
        "currentBaseFee": "7",
        "blockHashes": {
            "0": "0xe729de3fec21e30bea3d56adb01ed14bc107273c2775f9355afb10f594a10d9e"
        }
    },
    "pre": {
        "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
            "nonce": "0",
            "balance": "1000000000000000000",
            "code": "",
            "storage": {}
        }
    }
})";

static const std::string complex_json = R"({
    "test1": {
        "_info": {
            "labels": {
                "0": "first_tx",
                "1": "second_tx"
            }
        },
        "env": {
            "currentBaseFee": "0x0a",
            "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "currentDifficulty": "0x020000",
            "currentGasLimit": "0xff112233445566",
            "currentNumber": "0x01",
            "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
            "currentTimestamp": "0x03e8"
        },
        "post": {
            "London": [
                {
                    "hash": "0xe8010ce590f401c9d61fef8ab05bea9bcec24281b795e5868809bc4e515aa530",
                    "indexes": {
                        "data": 0,
                        "gas": 0,
                        "value": 0
                    },
                    "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                }
            ]
        }
    }
})";

static const std::string state_json = R"({
    "env": {
        "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
        "currentDifficulty": "0x20000",
        "currentGasLimit": "0xff112233445566",
        "currentNumber": "1",
        "currentTimestamp": "1000",
        "currentBaseFee": "7",
        "blockHashes": {
            "0": "0xe729de3fec21e30bea3d56adb01ed14bc107273c2775f9355afb10f594a10d9e"
        }
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

static void BM_GlazeJsonParse(benchmark::State& state) {
    for (auto _ : state) {
        auto result = glz::read_json<glz::json_t>(state_json);
        benchmark::DoNotOptimize(result);
    }
}

static void BM_GlazeParse(benchmark::State& state) {
    for (auto _ : state) {
        glz::json_t result;
        auto ec = glz::read_json(result, large_json);
        benchmark::DoNotOptimize(ec);
        benchmark::DoNotOptimize(result);
    }
}

static void BM_GlazeParseComplex(benchmark::State& state) {
    for (auto _ : state) {
        glz::json_t result;
        auto ec = glz::read_json(result, complex_json);
        benchmark::DoNotOptimize(ec);
        benchmark::DoNotOptimize(result);
    }
}

static void BM_GlazeSerialize(benchmark::State& state) {
    glz::json_t obj;
    auto ec = glz::read_json(obj, complex_json);
    if (!ec) {
        state.SkipWithError("Failed to parse JSON");
        return;
    }
    for (auto _ : state) {
        auto json = glz::write_json(obj);
        benchmark::DoNotOptimize(json);
    }
}

static void BM_GlazeStateTestParse(benchmark::State& state) {
    for (auto _ : state) {
        auto result = glz::read_json<StateTransitionTest>(state_json).value();
        benchmark::DoNotOptimize(result);
    }
}

static void BM_GlazeStateTestSerialize(benchmark::State& state) {
    auto obj = glz::read_json<StateTransitionTest>(state_json).value();
    for (auto _ : state) {
        auto json = glz::write_json(obj);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK(BM_GlazeJsonParse);
BENCHMARK(BM_GlazeParse);
BENCHMARK(BM_GlazeParseComplex);
BENCHMARK(BM_GlazeSerialize);
BENCHMARK(BM_GlazeStateTestParse);
BENCHMARK(BM_GlazeStateTestSerialize);

BENCHMARK_MAIN(); 
