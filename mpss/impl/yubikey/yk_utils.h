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

using mpss::SecureByteVector;
using mpss::SecureString;

/**
 * @brief Get the target YubiKey serial number from the environment variable MPSS_YUBIKEY_SERIAL.
 *
 * When set, MPSS iterates through available smart card readers and connects to the
 * YubiKey whose serial number matches. Useful on machines with multiple YubiKeys.
 * @return The serial number, or std::nullopt if not set or invalid.
 */
std::optional<std::uint32_t> get_serial_from_env();

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
 * then to the hardcoded default (YKPIV_PINPOLICY_ONCE).
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
 * then to the hardcoded default (YKPIV_TOUCHPOLICY_NEVER).
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
 * @brief Get the PIV slot name (for logging/debugging).
 * @param slot The PIV slot number.
 * @return Human-readable slot name.
 */
std::string_view get_slot_name(std::uint8_t slot);

} // namespace mpss::impl::yubikey::utils
