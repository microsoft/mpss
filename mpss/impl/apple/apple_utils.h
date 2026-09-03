// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace mpss::impl::os::utils
{

enum class AppleOperationResult
{
    operational_error,
    expected_negative,
    success,
    invalid_result
};

[[nodiscard]]
AppleOperationResult decode_apple_result(std::int32_t result) noexcept;

[[nodiscard]]
std::string take_secure_enclave_error();

[[nodiscard]]
std::string take_keychain_error();

void report_secure_enclave_error(std::string_view operation);

void report_keychain_error(std::string_view operation);

void report_invalid_apple_result(std::string_view source, std::string_view operation, std::int32_t result);

[[nodiscard]]
bool handle_secure_enclave_verification_result(std::int32_t result, std::string_view operation);

[[nodiscard]]
bool handle_keychain_verification_result(std::int32_t result, std::string_view operation);

// Removes the name from both tiers rather than from whichever one an open resolved to, so that a
// name reported as deleted is free in every tier a later open would consult. A tier that cannot be
// read fails the deletion instead of leaving the name silently held.
[[nodiscard]]
bool delete_key_from_all_tiers(const std::string &name);

} // namespace mpss::impl::os::utils
