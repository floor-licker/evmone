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
            } else {
                value = "0x" + hex(self);
            }
        };
    };

    // For hex string to bytes conversion
    template <>
    struct meta<evmc::bytes> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (!value.is_string()) {
                    throw std::invalid_argument("bytes value must be a string");
                }
                const auto s = value.template get<std::string>();
                if (!s.starts_with("0x")) {
                    throw std::invalid_argument("bytes value must start with 0x");
                }
                self = evmc::from_hex(s).value();
            } else {
                value = "0x" + evmc::hex(self);
            }
        };
    };

    // For hex string to address conversion
    template <>
    struct meta<evmc::address> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                if (!value.is_string()) {
                    throw std::invalid_argument("address value must be a string");
                }
                const auto s = value.template get<std::string>();
                if (!s.starts_with("0x")) {
                    throw std::invalid_argument("address value must start with 0x");
                }
                auto result = evmc::from_hex<evmc::address>(s);
                if (!result) {
                    throw std::invalid_argument("invalid address format: " + s);
                }
                self = result.value();
            } else {
                value = "0x" + evmc::hex(self);
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
            } else {
                if (is_zero(self)) {
                    value = "0x0";
                } else {
                    value = "0x" + evmc::hex(self);
                }
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
            } else {
                value = "0x" + intx::hex(self);
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
            } else {
                value = "0x" + hex(self);
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
            } else {
                value = "0x" + hex(self);
            }
        };
    };

    // For BlockInfoWithRev
    template <>
    struct meta<evmone::test::state::BlockInfoWithRev> {
        static constexpr auto value = [](auto&& self, auto&& value, evmc_revision rev) {
            if constexpr (glz::is_reading) {
                // Validate required fields
                const std::array<std::string, 4> required_fields = {
                    "currentNumber", "currentTimestamp", "currentGasLimit", "currentCoinbase"
                };
                for (const auto& field : required_fields) {
                    if (!value.contains(field)) {
                        throw std::invalid_argument("missing required field: " + field);
                    }
                }

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
            } else {
                // Write required fields
                value["currentNumber"] = "0x" + hex(self.number);
                value["currentTimestamp"] = "0x" + hex(self.timestamp);
                value["currentGasLimit"] = "0x" + hex(self.gas_limit);
                value["currentCoinbase"] = "0x" + evmc::hex(self.coinbase);
                
                // Write optional fields
                if (self.parent_timestamp)
                    value["parentTimestamp"] = "0x" + hex(self.parent_timestamp);
                if (self.parent_difficulty)
                    value["parentDifficulty"] = "0x" + hex(self.parent_difficulty);
                if (!is_zero(self.parent_ommers_hash))
                    value["parentUncleHash"] = "0x" + evmc::hex(self.parent_ommers_hash);
                if (self.excess_blob_gas)
                    value["currentExcessBlobGas"] = "0x" + hex(*self.excess_blob_gas);
                
                // Write difficulty/randao based on revision
                if (rev >= EVMC_PARIS) {
                    value["currentRandom"] = "0x" + evmc::hex(self.prev_randao);
                } else {
                    value["currentDifficulty"] = "0x" + hex(self.difficulty);
                }
                
                // Write base fee if needed
                if (rev >= EVMC_LONDON) {
                    value["currentBaseFee"] = "0x" + hex(self.base_fee);
                }
                
                // Write withdrawals and ommers
                if (!self.withdrawals.empty()) {
                    value["withdrawals"] = self.withdrawals;
                }
                if (!self.ommers.empty()) {
                    value["ommers"] = self.ommers;
                }
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
            } else {
                auto& obj = value["blockHashes"].get<glz::json_t::object_t>();
                for (const auto& [num, hash] : self) {
                    obj[std::to_string(num)] = "0x" + evmc::hex(hash);
                }
            }
        };
    };

    // For Transaction
    template <>
    struct meta<evmone::test::state::Transaction> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                // Validate required fields
                if (!value.contains("data") && !value.contains("input")) {
                    throw std::invalid_argument("transaction missing data/input field");
                }
                if (!value.contains("gasLimit") && !value.contains("gas")) {
                    throw std::invalid_argument("transaction missing gas/gasLimit field");
                }

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
            } else {
                // Write common fields
                meta<evmone::test::state::TransactionCommon>::value(self, value);
                
                // Write data and gas fields
                value["data"] = "0x" + evmc::hex(self.data);
                value["gasLimit"] = "0x" + hex(self.gas_limit);
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
            } else {
                // Write gas price fields based on type
                if (self.type == evmone::test::state::Transaction::Type::legacy) {
                    value["gasPrice"] = "0x" + intx::hex(self.max_gas_price);
                } else {
                    value["maxFeePerGas"] = "0x" + intx::hex(self.max_gas_price);
                    value["maxPriorityFeePerGas"] = "0x" + intx::hex(self.max_priority_gas_price);
                }

                // Write other common fields
                if (self.chain_id)
                    value["chainId"] = "0x" + hex(self.chain_id);
                if (self.nonce)
                    value["nonce"] = "0x" + hex(self.nonce);
                if (self.to)
                    value["to"] = "0x" + evmc::hex(*self.to);
                if (!is_zero(self.value))
                    value["value"] = "0x" + intx::hex(self.value);
                if (!self.access_list.empty())
                    value["accessList"] = self.access_list;
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
            } else {
                for (const auto& [addr, acc] : self) {
                    auto& acc_obj = value[hex0x(addr)].get<glz::json_t::object_t>();
                    acc_obj["nonce"] = "0x" + hex(acc.nonce);
                    acc_obj["balance"] = "0x" + intx::hex(acc.balance);
                    acc_obj["code"] = "0x" + evmc::hex(acc.code);
                    
                    auto& storage_obj = acc_obj["storage"].get<glz::json_t::object_t>();
                    for (const auto& [key, val] : acc.storage) {
                        storage_obj[hex0x(key)] = hex0x(val);
                    }
                }
            }
        };
    };

    // For StateTransitionTest
    template <>
    struct meta<evmone::test::StateTransitionTest> {
        static constexpr auto value = object(
            "name", &StateTransitionTest::name,
            "pre_state", &StateTransitionTest::pre_state,
            "multi_tx", &StateTransitionTest::multi_tx,
            "block_hashes", &StateTransitionTest::block_hashes,
            "input_labels", &StateTransitionTest::input_labels,
            "cases", &StateTransitionTest::cases
        );
    };

    // For StateTransitionTest::Case
    template <>
    struct meta<evmone::test::StateTransitionTest::Case> {
        static constexpr auto value = object(
            "revision", &StateTransitionTest::Case::revision,
            "expectations", &StateTransitionTest::Case::expectations,
            "block_info", &StateTransitionTest::Case::block_info
        );
    };

    // For StateTransitionTest::Case::Expectation
    template <>
    struct meta<evmone::test::StateTransitionTest::Case::Expectation> {
        static constexpr auto value = object(
            "indexes", &StateTransitionTest::Case::Expectation::indexes,
            "hash", &StateTransitionTest::Case::Expectation::state_hash,
            "logs", &StateTransitionTest::Case::Expectation::logs_hash,
            "expectException", &StateTransitionTest::Case::Expectation::exception
        );
    };

    // For TestMultiTransaction
    template <>
    struct meta<evmone::test::TestMultiTransaction> {
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

    // For TestMultiTransaction::Indexes
    template <>
    struct meta<evmone::test::TestMultiTransaction::Indexes> {
        static constexpr auto value = object(
            "data", &TestMultiTransaction::Indexes::input,
            "gas", &TestMultiTransaction::Indexes::gas_limit,
            "value", &TestMultiTransaction::Indexes::value
        );
    };

    // Update AccessList to use object style
    template <>
    struct meta<evmone::test::state::AccessList> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                auto [addr, storage_keys] = glz::read<std::tuple<
                    evmc::address,
                    std::vector<evmc::bytes32>
                >>(value, {"address", "storageKeys"});
                self.address = addr;
                self.storage_keys = std::move(storage_keys);
            } else {
                value["address"] = "0x" + evmc::hex(self.address);
                auto& keys = value["storageKeys"].get<std::vector<std::string>>();
                for (const auto& key : self.storage_keys) {
                    keys.push_back("0x" + evmc::hex(key));
                }
            }
        };
    };

    // For state::TransactionReceipt
    template <>
    struct meta<state::TransactionReceipt> {
        static constexpr auto value = object(
            "transactionHash", &state::TransactionReceipt::transaction_hash,
            "gasUsed", &state::TransactionReceipt::gas_used,
            "cumulativeGasUsed", &state::TransactionReceipt::cumulative_gas_used,
            "blockHash", &state::TransactionReceipt::block_hash,
            "contractAddress", &state::TransactionReceipt::contract_address,
            "logsBloom", &state::TransactionReceipt::logs_bloom_filter,
            "logs", &state::TransactionReceipt::logs,
            "status", &state::TransactionReceipt::status,
            "transactionIndex", &state::TransactionReceipt::transaction_index
        );
    };

    // For blockchain test types
    template <>
    struct meta<BlockchainTest> {
        static constexpr auto value = object(
            "name", &BlockchainTest::name,
            "network", &BlockchainTest::network,
            "sealEngine", &BlockchainTest::seal_engine,
            "genesisBlockHeader", &BlockchainTest::genesis_header,
            "pre", &BlockchainTest::genesis_state,
            "lastblockhash", &BlockchainTest::last_block_hash,
            "blocks", &BlockchainTest::blocks
        );
    };

    template <>
    struct meta<BlockchainTest::Block> {
        static constexpr auto value = object(
            "rlp", &BlockchainTest::Block::rlp,
            "blockHeader", &BlockchainTest::Block::header,
            "transactions", &BlockchainTest::Block::transactions,
            "uncleHeaders", &BlockchainTest::Block::uncle_headers
        );
    };

    // For state::Log
    template <>
    struct meta<state::Log> {
        static constexpr auto value = object(
            "address", &state::Log::addr,
            "topics", &state::Log::topics,
            "data", &state::Log::data,
            "blockNumber", &state::Log::block_number,
            "blockHash", &state::Log::block_hash,
            "transactionHash", &state::Log::transaction_hash,
            "transactionIndex", &state::Log::transaction_index,
            "logIndex", &state::Log::log_index
        );
    };

    // For EOF validation types
    template <>
    struct meta<EOFContainer> {
        static constexpr auto value = object(
            "code", &EOFContainer::code,
            "kind", &EOFContainer::kind,
            "version", &EOFContainer::version,
            "types", &EOFContainer::types,
            "data", &EOFContainer::data
        );
    };

    template <>
    struct meta<EOFValidationTestCase> {
        static constexpr auto value = object(
            "name", &EOFValidationTestCase::name,
            "container", &EOFValidationTestCase::container,
            "kind", &EOFValidationTestCase::kind,
            "error", &EOFValidationTestCase::error
        );
    };

    // For ContainerKind
    template <>
    struct meta<ContainerKind> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto s = value.template get<std::string>();
                if (s == "INITCODE")
                    self = ContainerKind::initcode;
                else if (s == "RUNTIME")
                    self = ContainerKind::runtime;
                else
                    throw std::invalid_argument("invalid container kind: " + s);
            } else {
                value = self == ContainerKind::initcode ? "INITCODE" : "RUNTIME";
            }
        };
    };

    // For EOFValidationError
    template <>
    struct meta<EOFValidationError> {
        static constexpr auto value = [](auto&& self, auto&& value) {
            if constexpr (glz::is_reading) {
                const auto s = value.template get<std::string>();
                if (s == "success") self = EOFValidationError::success;
                else if (s == "EOF_InvalidPrefix") self = EOFValidationError::invalid_prefix;
                else if (s == "EOF_UnknownVersion") self = EOFValidationError::eof_version_unknown;
                else if (s == "EOF_IncompleteSectionSize") self = EOFValidationError::incomplete_section_size;
                else if (s == "EOF_IncompleteSectionNumber") self = EOFValidationError::incomplete_section_number;
                else if (s == "EOF_HeaderTerminatorMissing") self = EOFValidationError::header_terminator_missing;
                else if (s == "EOF_TypeSectionMissing") self = EOFValidationError::type_section_missing;
                else if (s == "EOF_CodeSectionMissing") self = EOFValidationError::code_section_missing;
                else if (s == "EOF_DataSectionMissing") self = EOFValidationError::data_section_missing;
                else if (s == "EOF_ZeroSectionSize") self = EOFValidationError::zero_section_size;
                else if (s == "EOF_SectionHeadersNotTerminated") self = EOFValidationError::section_headers_not_terminated;
                else if (s == "EOF_InvalidSectionBodiesSize") self = EOFValidationError::invalid_section_bodies_size;
                else if (s == "EOF_UnreachableCodeSections") self = EOFValidationError::unreachable_code_sections;
                else if (s == "EOF_UndefinedInstruction") self = EOFValidationError::undefined_instruction;
                else if (s == "EOF_TruncatedImmediate") self = EOFValidationError::truncated_instruction;
                else if (s == "EOF_InvalidJumpDestination") self = EOFValidationError::invalid_rjump_destination;
                else if (s == "EOF_TooManyCodeSections") self = EOFValidationError::too_many_code_sections;
                else if (s == "EOF_InvalidTypeSectionSize") self = EOFValidationError::invalid_type_section_size;
                else if (s == "EOF_InvalidFirstSectionType") self = EOFValidationError::invalid_first_section_type;
                else if (s == "EOF_InvalidMaxStackHeight") self = EOFValidationError::invalid_max_stack_height;
                else if (s == "EOF_MaxStackHeightExceeded") self = EOFValidationError::max_stack_height_above_limit;
                else if (s == "EOF_InputsOutputsNumAboveLimit") self = EOFValidationError::inputs_outputs_num_above_limit;
                else if (s == "EOF_InvalidCodeTermination") self = EOFValidationError::no_terminating_instruction;
                else if (s == "EOF_ConflictingStackHeight") self = EOFValidationError::stack_height_mismatch;
                else if (s == "EOF_InvalidNumberOfOutputs") self = EOFValidationError::stack_higher_than_outputs_required;
                else if (s == "EOF_UnreachableCode") self = EOFValidationError::unreachable_instructions;
                else if (s == "EOF_StackUnderflow") self = EOFValidationError::stack_underflow;
                else if (s == "EOF_StackOverflow") self = EOFValidationError::stack_overflow;
                else if (s == "EOF_InvalidCodeSectionIndex") self = EOFValidationError::invalid_code_section_index;
                else if (s == "EOF_InvalidDataloadnIndex") self = EOFValidationError::invalid_dataloadn_index;
                else if (s == "EOF_JumpfDestinationIncompatibleOutputs") self = EOFValidationError::jumpf_destination_incompatible_outputs;
                else if (s == "EOF_InvalidNonReturningFlag") self = EOFValidationError::invalid_non_returning_flag;
                else if (s == "EOF_CallfToNonReturningFunction") self = EOFValidationError::callf_to_non_returning_function;
                else throw std::invalid_argument("invalid EOF validation error: " + s);
            } else {
                switch (self) {
                    case EOFValidationError::success: value = "success"; break;
                    case EOFValidationError::invalid_prefix: value = "EOF_InvalidPrefix"; break;
                    case EOFValidationError::eof_version_unknown: value = "EOF_UnknownVersion"; break;
                    case EOFValidationError::incomplete_section_size: value = "EOF_IncompleteSectionSize"; break;
                    case EOFValidationError::incomplete_section_number: value = "EOF_IncompleteSectionNumber"; break;
                    case EOFValidationError::header_terminator_missing: value = "EOF_HeaderTerminatorMissing"; break;
                    case EOFValidationError::type_section_missing: value = "EOF_TypeSectionMissing"; break;
                    case EOFValidationError::code_section_missing: value = "EOF_CodeSectionMissing"; break;
                    case EOFValidationError::data_section_missing: value = "EOF_DataSectionMissing"; break;
                    case EOFValidationError::zero_section_size: value = "EOF_ZeroSectionSize"; break;
                    case EOFValidationError::section_headers_not_terminated: value = "EOF_SectionHeadersNotTerminated"; break;
                    case EOFValidationError::invalid_section_bodies_size: value = "EOF_InvalidSectionBodiesSize"; break;
                    case EOFValidationError::unreachable_code_sections: value = "EOF_UnreachableCodeSections"; break;
                    case EOFValidationError::undefined_instruction: value = "EOF_UndefinedInstruction"; break;
                    case EOFValidationError::truncated_instruction: value = "EOF_TruncatedImmediate"; break;
                    case EOFValidationError::invalid_rjump_destination: value = "EOF_InvalidJumpDestination"; break;
                    case EOFValidationError::too_many_code_sections: value = "EOF_TooManyCodeSections"; break;
                    case EOFValidationError::invalid_type_section_size: value = "EOF_InvalidTypeSectionSize"; break;
                    case EOFValidationError::invalid_first_section_type: value = "EOF_InvalidFirstSectionType"; break;
                    case EOFValidationError::invalid_max_stack_height: value = "EOF_InvalidMaxStackHeight"; break;
                    case EOFValidationError::max_stack_height_above_limit: value = "EOF_MaxStackHeightExceeded"; break;
                    case EOFValidationError::inputs_outputs_num_above_limit: value = "EOF_InputsOutputsNumAboveLimit"; break;
                    case EOFValidationError::no_terminating_instruction: value = "EOF_InvalidCodeTermination"; break;
                    case EOFValidationError::stack_height_mismatch: value = "EOF_ConflictingStackHeight"; break;
                    case EOFValidationError::stack_higher_than_outputs_required: value = "EOF_InvalidNumberOfOutputs"; break;
                    case EOFValidationError::unreachable_instructions: value = "EOF_UnreachableCode"; break;
                    case EOFValidationError::stack_underflow: value = "EOF_StackUnderflow"; break;
                    case EOFValidationError::stack_overflow: value = "EOF_StackOverflow"; break;
                    case EOFValidationError::invalid_code_section_index: value = "EOF_InvalidCodeSectionIndex"; break;
                    case EOFValidationError::invalid_dataloadn_index: value = "EOF_InvalidDataloadnIndex"; break;
                    case EOFValidationError::jumpf_destination_incompatible_outputs: value = "EOF_JumpfDestinationIncompatibleOutputs"; break;
                    case EOFValidationError::invalid_non_returning_flag: value = "EOF_InvalidNonReturningFlag"; break;
                    case EOFValidationError::callf_to_non_returning_function: value = "EOF_CallfToNonReturningFunction"; break;
                    default: value = "unknown";
                }
            }
        };
    };

    // For container-related types
    template <>
    struct meta<evmone::test::state::ContainerSection> {
        static constexpr auto value = object(
            "size", &ContainerSection::size,
            "offset", &ContainerSection::offset,
            "data", &ContainerSection::data
        );
    };

    template <>
    struct meta<evmone::test::state::ContainerType> {
        static constexpr auto value = object(
            "inputs", &ContainerType::inputs,
            "outputs", &ContainerType::outputs,
            "max_stack_height", &ContainerType::max_stack_height
        );
    };
} 