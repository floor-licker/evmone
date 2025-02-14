// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "statetest.hpp"
#include "../utils/glaze_meta.hpp"

namespace evmone::test
{
[[nodiscard]] std::string get_invalid_tx_message(state::ErrorCode errc) noexcept
{
    using namespace state;
    switch (errc)
    {
    case SUCCESS:
        return "";
    case INTRINSIC_GAS_TOO_LOW:
        return "TR_IntrinsicGas";
    case TX_TYPE_NOT_SUPPORTED:
        return "TR_TypeNotSupported";
    case INSUFFICIENT_FUNDS:
        return "TR_NoFunds";
    case NONCE_HAS_MAX_VALUE:
        return "TR_NonceHasMaxValue:";
    case NONCE_TOO_HIGH:
        return "TR_NonceTooHigh";
    case NONCE_TOO_LOW:
        return "TR_NonceTooLow";
    case TIP_GT_FEE_CAP:
        return "TR_TipGtFeeCap";
    case FEE_CAP_LESS_THEN_BLOCKS:
        return "TR_FeeCapLessThanBlocks";
    case GAS_LIMIT_REACHED:
        return "TR_GasLimitReached";
    case SENDER_NOT_EOA:
        return "SenderNotEOA";
    case INIT_CODE_SIZE_LIMIT_EXCEEDED:
        return "TR_InitCodeLimitExceeded";
    case CREATE_BLOB_TX:
        return "TR_BLOBCREATE";
    case EMPTY_BLOB_HASHES_LIST:
        return "TR_EMPTYBLOB";
    case INVALID_BLOB_HASH_VERSION:
        return "TR_BLOBVERSION_INVALID";
    case BLOB_GAS_LIMIT_EXCEEDED:
        return "TR_BLOBLIST_OVERSIZE";
    case UNKNOWN_ERROR:
        return "Unknown error";
    default:
        assert(false);
        return "Wrong error code";
    }
}


glz::json_t to_json(const TestState& state)
{
    glz::json_t j = glz::json_t::object();
    for (const auto& [addr, acc] : state)
    {
        auto& j_acc = j[hex0x(addr)] = glz::json_t::object();
        j_acc["nonce"] = hex0x(acc.nonce);
        j_acc["balance"] = hex0x(acc.balance);
        j_acc["code"] = hex0x(bytes_view(acc.code.data(), acc.code.size()));

        auto& j_storage = j_acc["storage"] = glz::json_t::object();
        for (const auto& [key, val] : acc.storage)
        {
            if (!is_zero(val))
                j_storage[hex0x(key)] = hex0x(val);
        }
    }
    return j;
}

void export_state_test(const StateTransitionTest& test, std::ostream& out)
{
    glz::json_t j;
    auto result = glz::write_json(test, glz::format::indent);
    out << result << std::endl;
}
}  // namespace evmone::test
