#pragma once

#include <evmc/evmc.hpp>
#include <glaze/glaze.hpp>
#include <intx/intx.hpp>

namespace glz {
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
    struct meta<evmc::bytes> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                self = evmc::from_hex(value.template get<std::string>()).value();
            }
        };
    };

    // For hex string to address conversion
    template <>
    struct meta<evmc::address> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                self = evmc::from_hex<evmc::address>(value.template get<std::string>()).value();
            }
        };
    };

    // For hash256 conversion
    template <>
    struct meta<evmc::bytes32> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto s = value.template get<std::string>();
                if (s == "0" || s == "0x0") {
                    self = {};
                    return;
                }
                const auto opt_hash = evmc::from_hex<evmc::bytes32>(s);
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

    // For integer types
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

    // For BlockInfoWithRev
    template <>
    struct meta<evmone::test::state::BlockInfoWithRev> {
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
                auto parent_uncle_hash = glz::get_value<evmc::bytes32>(value, "parentUncleHash").value_or(EmptyListHash);
                auto excess_blob_gas = glz::get_value<uint64_t>(value, "currentExcessBlobGas");

                // Handle difficulty/randao
                evmc::bytes32 prev_randao;
                int64_t current_difficulty;
                if (rev >= EVMC_PARIS) {
                    prev_randao = glz::read<evmc::bytes32>(value, "currentRandom");
                    current_difficulty = 0;
                } else {
                    current_difficulty = glz::read<int64_t>(value, "currentDifficulty");
                    prev_randao = intx::be::store<evmc::bytes32>(intx::uint256{current_difficulty});
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

                // Handle withdrawals and ommers
                std::vector<evmone::test::state::Withdrawal> withdrawals;
                std::vector<evmone::test::state::Ommer> ommers;
                if (rev >= EVMC_SHANGHAI) {
                    if (auto withdrawals_opt = glz::get_value<std::vector<evmone::test::state::Withdrawal>>(value, "withdrawals")) {
                        withdrawals = *withdrawals_opt;
                    }
                }
                if (auto ommers_opt = glz::get_value<std::vector<evmone::test::state::Ommer>>(value, "ommers")) {
                    ommers = std::move(*ommers_opt);
                }

                self = evmone::test::state::BlockInfo{
                    .number = number,
                    .timestamp = timestamp,
                    .parent_timestamp = parent_timestamp,
                    .gas_limit = gas_limit,
                    .coinbase = coinbase,
                    .difficulty = current_difficulty,
                    .parent_difficulty = parent_difficulty,
                    .parent_ommers_hash = parent_uncle_hash,
                    .prev_randao = prev_randao,
                    .parent_beacon_block_root = glz::get_value<evmc::bytes32>(value, "parentBeaconBlockRoot").value_or(evmc::bytes32{}),
                    .base_fee = base_fee,
                    .blob_gas_used = glz::get_value<uint64_t>(value, "blobGasUsed").value_or(0),
                    .excess_blob_gas = excess_blob_gas,
                    .blob_base_fee = evmone::test::state::compute_blob_gas_price(rev, excess_blob_gas),
                    .ommers = std::move(ommers),
                    .withdrawals = std::move(withdrawals),
                };
            }
        };
    };

    // For TestBlockHashes
    template <>
    struct meta<evmone::test::TestBlockHashes> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (auto block_hashes = glz::get_value<glz::json_t>(value, "blockHashes")) {
                    for (const auto& [num, hash] : block_hashes->items()) {
                        self[std::stoll(num)] = glz::read<evmc::bytes32>(hash);
                    }
                }
            }
        };
    };

    // For Transaction
    template <>
    struct meta<evmone::test::state::Transaction> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                // First read common fields
                meta<evmone::test::state::TransactionCommon>::value(self, value);

                // Handle data/input field
                if (auto data = glz::get_value<evmc::bytes>(value, "data")) {
                    self.data = *data;
                } else {
                    self.data = glz::read<evmc::bytes>(value, "input");
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

    // For TransactionCommon
    template <>
    struct meta<evmone::test::state::TransactionCommon> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                // Handle gas price fields
                if (auto gas_price = glz::get_value<intx::uint256>(value, "gasPrice")) {
                    self.type = evmone::test::state::Transaction::Type::legacy;
                    self.max_gas_price = *gas_price;
                    self.max_priority_gas_price = self.max_gas_price;
                    
                    // Check for invalid combination of fees
                    if (value.contains("maxFeePerGas") || value.contains("maxPriorityFeePerGas")) {
                        throw std::invalid_argument(
                            "invalid transaction: contains both legacy and EIP-1559 fees");
                    }
                } else {
                    self.type = evmone::test::state::Transaction::Type::eip1559;
                    auto [max_fee, max_priority_fee] = glz::read<std::tuple<intx::uint256, intx::uint256>>(
                        value, {"maxFeePerGas", "maxPriorityFeePerGas"}
                    );
                    self.max_gas_price = max_fee;
                    self.max_priority_gas_price = max_priority_fee;
                }

                // Read other common fields
                if (auto chain_id = glz::get_value<uint64_t>(value, "chainId")) {
                    self.chain_id = *chain_id;
                }
                if (auto nonce = glz::get_value<uint64_t>(value, "nonce")) {
                    self.nonce = *nonce;
                }
                if (auto to = glz::get_value<evmc::address>(value, "to")) {
                    self.to = *to;
                }
                if (auto value_field = glz::get_value<intx::uint256>(value, "value")) {
                    self.value = *value_field;
                }
                if (auto access_list = glz::get_value<std::vector<evmone::test::state::AccessList>>(value, "accessList")) {
                    self.access_list = *access_list;
                }
            }
        };
    };

    // For TestState
    template <>
    struct meta<evmone::test::TestState> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                for (const auto& [addr_str, acc_json] : value.items()) {
                    auto addr = glz::read<evmc::address>(addr_str);
                    auto [nonce, balance, code] = glz::read<std::tuple<
                        uint64_t, intx::uint256, evmc::bytes
                    >>(acc_json, {"nonce", "balance", "code"});

                    auto& acc = self[addr];
                    acc.nonce = nonce;
                    acc.balance = balance;
                    acc.code = code;

                    if (auto storage_opt = glz::get_value<std::map<evmc::bytes32, evmc::bytes32>>(acc_json, "storage")) {
                        acc.storage = std::move(*storage_opt);
                    }
                }
            }
        };
    };
} 