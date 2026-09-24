// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include "mpss/key_policy.h"
#include "mpss/secure_types.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace mpss::impl::yubikey::utils
{

/**
 * @brief Whether an environment variable value explicitly enables an opt-in.
 *
 * Matching is case-insensitive.
 * @param value The environment variable value.
 * @return true for 1, true, yes, or on; false otherwise.
 */
bool is_affirmative_environment_value(std::string_view value);

/**
 * @brief Reads the default YubiKey serial number from the environment variable MPSS_YUBIKEY_SERIAL.
 *
 * Name-based calls connect to the YubiKey whose serial number matches this default. The variable
 * counts as unset when it is absent or empty.
 * @param[out] serial The serial number, or std::nullopt when the variable is unset.
 * @return true if the variable is unset or holds a valid serial number, false, with the error
 * set, if it holds anything else.
 */
[[nodiscard]]
bool get_serial_from_env(std::optional<std::uint32_t> &serial);

// Match the reference format's device-ID bound while retaining support for leading zeros.
inline constexpr std::size_t max_serial_length = 256;

/** @brief Parse 1-max_serial_length decimal characters as a nonzero uint32_t serial; leading zeros are accepted. */
[[nodiscard]]
std::optional<std::uint32_t> parse_serial(std::string_view serial);

/**
 * @brief Get the YubiKey management key from the environment variable MPSS_YUBIKEY_MGM_KEY.
 *
 * Expected format: hex string (32, 48, or 64 characters).
 * @return The management key bytes, or std::nullopt if not set or invalid.
 */
SecureByteVector get_mgm_key_from_env();

/**
 * @brief Resolve the effective YubiKey PIN policy from a @ref KeyPolicy bitmask.
 *
 * If the YubiKey PIN policy field (bits 0-3) is non-zero, maps the value to the corresponding
 * ykpiv constant. Otherwise, falls back to the MPSS_YUBIKEY_PINPOLICY environment variable,
 * then to the hardcoded default (YKPIV_PINPOLICY_ONCE). The weakest environment value, 'never',
 * is honored only when MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE is set; otherwise the default is used.
 *
 * @param policy The key policy bitmask.
 * @return The ykpiv PIN policy constant.
 */
std::uint8_t resolve_pin_policy(KeyPolicy policy);

/**
 * @brief Resolve the effective YubiKey touch policy from a @ref KeyPolicy bitmask.
 *
 * If the YubiKey touch policy field (bits 4-7) is non-zero, maps the value to the corresponding
 * ykpiv constant. Otherwise, falls back to the MPSS_YUBIKEY_TOUCHPOLICY environment variable,
 * then to the hardcoded default (YKPIV_TOUCHPOLICY_CACHED). The weakest environment value, 'never',
 * is honored only when MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE is set; otherwise the default is used.
 *
 * @param policy The key policy bitmask.
 * @return The ykpiv touch policy constant.
 */
std::uint8_t resolve_touch_policy(KeyPolicy policy);

/**
 * @brief Convert mpss::Algorithm to YubiKey PIV algorithm constant.
 * @param algorithm The mpss::Algorithm.
 * @return The YubiKey PIV algorithm constant, or 0 if unsupported.
 */
std::uint8_t mpss_to_yk_algorithm(Algorithm algorithm);

/**
 * @brief Convert YubiKey PIV algorithm constant to MPSS Algorithm.
 * @param yk_algorithm The YubiKey PIV algorithm constant.
 * @return The MPSS algorithm, or Algorithm::unsupported if unknown.
 */
Algorithm yk_to_mpss_algorithm(std::uint8_t yk_algorithm);

/**
 * @brief Get the OpenSSL group name for an algorithm.
 * @param algorithm The MPSS algorithm.
 * @return The group name, or nullptr if the algorithm has no YubiKey-supported group.
 */
const char *get_group_name(Algorithm algorithm);

/**
 * @brief Get the PIV slot name (for logging/debugging).
 * @param slot The PIV slot number.
 * @return Human-readable slot name.
 */
std::string_view get_slot_name(std::uint8_t slot);

} // namespace mpss::impl::yubikey::utils
