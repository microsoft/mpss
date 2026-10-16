// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/apple/apple_utils.h"
#include "mpss/impl/apple/apple_api_wrapper.h"
#include "mpss/impl/apple/apple_result.h"
#include "mpss/impl/apple/apple_se_wrapper.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os::utils
{

namespace
{

template <typename GetLastError> std::string take_error(GetLastError get_last_error)
{
    const std::size_t error_size = get_last_error(nullptr, 0);
    if (0 == error_size)
    {
        return {};
    }

    std::string error(error_size, '\0');
    const std::size_t written = get_last_error(error.data(), error.size());
    if (written != error_size)
    {
        return {};
    }

    return error;
}

void report_error(std::string_view source, std::string_view operation, std::string detail)
{
    if (detail.empty())
    {
        mpss::utils::log_and_set_error("{} failed without {} error detail.", operation, source);
        return;
    }

    mpss::utils::log_and_set_error("{} failed: {}", operation, detail);
}

} // namespace

AppleOperationResult decode_apple_result(std::int32_t result) noexcept
{
    switch (result)
    {
    case MPSS_APPLE_RESULT_OPERATIONAL_ERROR:
        return AppleOperationResult::operational_error;
    case MPSS_APPLE_RESULT_EXPECTED_NEGATIVE:
        return AppleOperationResult::expected_negative;
    case MPSS_APPLE_RESULT_SUCCESS:
        return AppleOperationResult::success;
    default:
        return AppleOperationResult::invalid_result;
    }
}

std::string take_secure_enclave_error()
{
    return take_error(::MPSS_SE_GetLastError);
}

std::string take_keychain_error()
{
    return take_error(::MPSS_GetLastError);
}

void report_secure_enclave_error(std::string_view operation)
{
    report_error("Secure Enclave", operation, take_secure_enclave_error());
}

void report_keychain_error(std::string_view operation)
{
    report_error("Keychain", operation, take_keychain_error());
}

void report_invalid_apple_result(std::string_view source, std::string_view operation, std::int32_t result)
{
    mpss::utils::log_and_set_error("{} returned invalid result {} while attempting to {}.", source, result, operation);
}

bool handle_secure_enclave_verification_result(std::int32_t result, std::string_view operation)
{
    switch (decode_apple_result(result))
    {
    case AppleOperationResult::success:
        return true;
    case AppleOperationResult::expected_negative:
        return false;
    case AppleOperationResult::operational_error:
        report_secure_enclave_error(operation);
        return false;
    case AppleOperationResult::invalid_result:
        report_invalid_apple_result("Secure Enclave", operation, result);
        return false;
    }

    return false;
}

bool handle_keychain_verification_result(std::int32_t result, std::string_view operation)
{
    switch (decode_apple_result(result))
    {
    case AppleOperationResult::success:
        return true;
    case AppleOperationResult::expected_negative:
        return false;
    case AppleOperationResult::operational_error:
        report_keychain_error(operation);
        return false;
    case AppleOperationResult::invalid_result:
        report_invalid_apple_result("Keychain", operation, result);
        return false;
    }

    return false;
}

bool delete_key_from_all_tiers(const std::string &name)
{
    // Both tiers are always addressed. Stopping after the tier an open happened to resolve to would
    // report a name as deleted while another tier still holds it, and a later open would find that
    // one. Absence is success: each remover treats a name it does not hold as nothing to do.
    bool deleted = true;

    // The Secure Enclave remover clears an ordinary Keychain item and does not touch the enclave, so
    // it is called whether or not this machine has one: the item can outlive the context that
    // created it, and a name reported as deleted has to be free in every tier.
    if (!MPSS_SE_RemoveExistingKey(name.c_str()))
    {
        report_secure_enclave_error("delete key");
        deleted = false;
    }

    if (!MPSS_DeleteKey(name.c_str()))
    {
        report_keychain_error("delete key");
        deleted = false;
    }

    return deleted;
}

} // namespace mpss::impl::os::utils
