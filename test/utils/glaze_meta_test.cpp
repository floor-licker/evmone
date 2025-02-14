#include "../utils/glaze_meta.hpp"
#include <gtest/gtest.h>

TEST(GlazeMeta, SerializeDeserializeAddress)
{
    evmc::address addr = 0x1234_address;
    auto json = glz::write_json(addr);
    EXPECT_EQ(json, "\"0x0000000000000000000000000000000000001234\"");
    auto result = glz::read_json<evmc::address>(json);
    EXPECT_EQ(result.value(), addr);
}

TEST(GlazeMeta, SerializeDeserializeBytes32)
{
    evmc::bytes32 hash = 0x1234_bytes32;
    auto json = glz::write_json(hash);
    EXPECT_EQ(json, "\"0x0000000000000000000000000000000000000000000000000000000000001234\"");
    auto result = glz::read_json<evmc::bytes32>(json);
    EXPECT_EQ(result.value(), hash);
}

TEST(GlazeMeta, SerializeDeserializeUint256)
{
    intx::uint256 value = 0x1234;
    auto json = glz::write_json(value);
    EXPECT_EQ(json, "\"0x1234\"");
    auto result = glz::read_json<intx::uint256>(json);
    EXPECT_EQ(result.value(), value);
}

TEST(GlazeMeta, ErrorHandling)
{
    // Test invalid address format
    EXPECT_THROW(glz::read_json<evmc::address>("\"1234\""), std::invalid_argument);
    EXPECT_THROW(glz::read_json<evmc::address>("1234"), std::invalid_argument);
    
    // Test invalid bytes32 format
    EXPECT_THROW(glz::read_json<evmc::bytes32>("\"1234\""), std::invalid_argument);
    EXPECT_THROW(glz::read_json<evmc::bytes32>("1234"), std::invalid_argument);
    
    // Test invalid uint256 format
    EXPECT_THROW(glz::read_json<intx::uint256>("\"xyz\""), std::invalid_argument);
}

TEST(GlazeMeta, SerializeDeserializeTestState)
{
    evmone::test::TestState state;
    auto& acc = state[0x1234_address];
    acc.nonce = 1;
    acc.balance = 0x1000;
    acc.code = evmc::from_hex("60606040").value();
    acc.storage[0x1234_bytes32] = 0x5678_bytes32;

    auto json = glz::write_json(state);
    auto result = glz::read_json<evmone::test::TestState>(json);
    EXPECT_EQ(result.value(), state);
}

TEST(GlazeMeta, SerializeDeserializeTransaction)
{
    evmone::test::state::Transaction tx;
    tx.type = evmone::test::state::Transaction::Type::eip1559;
    tx.max_gas_price = 0x1000;
    tx.max_priority_gas_price = 0x100;
    tx.gas_limit = 21000;
    tx.to = 0x1234_address;
    tx.value = 0x1000;
    tx.data = evmc::from_hex("60606040").value();

    auto json = glz::write_json(tx);
    auto result = glz::read_json<evmone::test::state::Transaction>(json);
    EXPECT_EQ(result.value(), tx);
}

TEST(GlazeMeta, SerializeDeserializeAccessList)
{
    evmone::test::state::AccessList access_list;
    access_list.address = 0x1234_address;
    access_list.storage_keys = {0x1234_bytes32, 0x5678_bytes32};

    auto json = glz::write_json(access_list);
    auto result = glz::read_json<evmone::test::state::AccessList>(json);
    EXPECT_EQ(result.value(), access_list);
}

TEST(GlazeMeta, SerializeDeserializeBlockHashes)
{
    evmone::test::TestBlockHashes hashes;
    hashes[1] = 0x1234_bytes32;
    hashes[2] = 0x5678_bytes32;

    auto json = glz::write_json(hashes);
    auto result = glz::read_json<evmone::test::TestBlockHashes>(json);
    EXPECT_EQ(result.value(), hashes);
}

TEST(GlazeMeta, SerializeDeserializeEOFValidationError)
{
    // Test success case
    {
        const auto json = "\"success\"";
        const auto result = glz::read_json<EOFValidationError>(json);
        EXPECT_EQ(result.value(), EOFValidationError::success);
    }

    // Test error case
    {
        const auto json = "\"EOF_InvalidPrefix\"";
        const auto result = glz::read_json<EOFValidationError>(json);
        EXPECT_EQ(result.value(), EOFValidationError::invalid_prefix);
    }

    // Test invalid input
    EXPECT_THROW(glz::read_json<EOFValidationError>("\"invalid_error\""), std::invalid_argument);
}

TEST(GlazeMeta, SerializeDeserializeContainerSection)
{
    evmone::test::state::ContainerSection section{
        .size = 10,
        .offset = 20,
        .data = evmc::from_hex("60606040").value()
    };

    auto json = glz::write_json(section);
    auto result = glz::read_json<evmone::test::state::ContainerSection>(json);
    EXPECT_EQ(result.value(), section);
}

TEST(GlazeMeta, SerializeDeserializeContainerType)
{
    evmone::test::state::ContainerType type{
        .inputs = 2,
        .outputs = 1,
        .max_stack_height = 16
    };

    auto json = glz::write_json(type);
    auto result = glz::read_json<evmone::test::state::ContainerType>(json);
    EXPECT_EQ(result.value(), type);
}

TEST(GlazeMeta, SerializeDeserializeEOFValidationErrorAllCases)
{
    const std::vector<std::pair<EOFValidationError, std::string>> test_cases = {
        {EOFValidationError::success, "success"},
        {EOFValidationError::invalid_prefix, "EOF_InvalidPrefix"},
        {EOFValidationError::eof_version_unknown, "EOF_UnknownVersion"},
        {EOFValidationError::incomplete_section_size, "EOF_IncompleteSectionSize"},
        {EOFValidationError::incomplete_section_number, "EOF_IncompleteSectionNumber"},
        {EOFValidationError::header_terminator_missing, "EOF_HeaderTerminatorMissing"},
        {EOFValidationError::type_section_missing, "EOF_TypeSectionMissing"},
        {EOFValidationError::code_section_missing, "EOF_CodeSectionMissing"},
        {EOFValidationError::data_section_missing, "EOF_DataSectionMissing"},
        {EOFValidationError::zero_section_size, "EOF_ZeroSectionSize"},
        {EOFValidationError::section_headers_not_terminated, "EOF_SectionHeadersNotTerminated"},
        {EOFValidationError::invalid_section_bodies_size, "EOF_InvalidSectionBodiesSize"},
        {EOFValidationError::unreachable_code_sections, "EOF_UnreachableCodeSections"},
        {EOFValidationError::undefined_instruction, "EOF_UndefinedInstruction"},
        {EOFValidationError::truncated_instruction, "EOF_TruncatedImmediate"},
        {EOFValidationError::invalid_rjump_destination, "EOF_InvalidJumpDestination"},
        {EOFValidationError::too_many_code_sections, "EOF_TooManyCodeSections"},
        {EOFValidationError::invalid_type_section_size, "EOF_InvalidTypeSectionSize"},
        {EOFValidationError::invalid_first_section_type, "EOF_InvalidFirstSectionType"},
        {EOFValidationError::invalid_max_stack_height, "EOF_InvalidMaxStackHeight"},
        {EOFValidationError::max_stack_height_above_limit, "EOF_MaxStackHeightExceeded"},
        {EOFValidationError::inputs_outputs_num_above_limit, "EOF_InputsOutputsNumAboveLimit"},
        {EOFValidationError::no_terminating_instruction, "EOF_InvalidCodeTermination"},
        {EOFValidationError::stack_height_mismatch, "EOF_ConflictingStackHeight"},
        {EOFValidationError::stack_higher_than_outputs_required, "EOF_InvalidNumberOfOutputs"},
        {EOFValidationError::unreachable_instructions, "EOF_UnreachableCode"},
        {EOFValidationError::stack_underflow, "EOF_StackUnderflow"},
        {EOFValidationError::stack_overflow, "EOF_StackOverflow"},
        {EOFValidationError::invalid_code_section_index, "EOF_InvalidCodeSectionIndex"},
        {EOFValidationError::invalid_dataloadn_index, "EOF_InvalidDataloadnIndex"},
        {EOFValidationError::jumpf_destination_incompatible_outputs, "EOF_JumpfDestinationIncompatibleOutputs"},
        {EOFValidationError::invalid_non_returning_flag, "EOF_InvalidNonReturningFlag"},
        {EOFValidationError::callf_to_non_returning_function, "EOF_CallfToNonReturningFunction"}
    };

    for (const auto& [error, str] : test_cases) {
        auto json = glz::write_json(error);
        EXPECT_EQ(json, "\"" + str + "\"");
        auto result = glz::read_json<EOFValidationError>(json);
        EXPECT_EQ(result.value(), error);
    }
}

TEST(GlazeMeta, SerializeDeserializeContainerKind)
{
    // Test initcode
    {
        const auto kind = ContainerKind::initcode;
        auto json = glz::write_json(kind);
        EXPECT_EQ(json, "\"INITCODE\"");
        auto result = glz::read_json<ContainerKind>(json);
        EXPECT_EQ(result.value(), kind);
    }

    // Test runtime
    {
        const auto kind = ContainerKind::runtime;
        auto json = glz::write_json(kind);
        EXPECT_EQ(json, "\"RUNTIME\"");
        auto result = glz::read_json<ContainerKind>(json);
        EXPECT_EQ(result.value(), kind);
    }

    // Test invalid input
    EXPECT_THROW(glz::read_json<ContainerKind>("\"INVALID\""), std::invalid_argument);
} 