// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/yubikey/yk_utils.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <format>
#include <ykpiv/ykpiv.h>

namespace
{

constexpr std::uint8_t default_pin_policy = YKPIV_PINPOLICY_ONCE;
constexpr std::uint8_t default_touch_policy = YKPIV_TOUCHPOLICY_CACHED;

/** @brief Convert a string to lowercase. */
std::string to_lower(std::string_view str)
{
    std::string result{str};
    std::ranges::transform(result, result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

/**
 * @brief Whether an env-driven downgrade to a 'never' pin/touch policy is explicitly permitted.
 *
 * A 'never' policy is permanent and unrepairable once baked into a key at generation, so it is
 * only honored from the environment when MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE is set to an
 * affirmative value (1, true, yes, on). It defaults to off.
 */
bool policy_downgrade_allowed()
{
    const char *env_ptr = std::getenv("MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE");
    return nullptr != env_ptr && mpss::impl::yubikey::utils::is_affirmative_environment_value(env_ptr);
}

/** @brief Read YubiKey PIN policy from the MPSS_YUBIKEY_PINPOLICY environment variable. */
std::uint8_t get_pin_policy_from_env()
{
    const char *env_ptr = std::getenv("MPSS_YUBIKEY_PINPOLICY");
    if (nullptr == env_ptr)
    {
        mpss::utils::log_trace("MPSS_YUBIKEY_PINPOLICY environment variable not set. Defaulting to 'once' policy.");
        return default_pin_policy;
    }

    const std::string value = to_lower(env_ptr);
    if ("default" == value)
    {
        return YKPIV_PINPOLICY_DEFAULT;
    }
    if ("never" == value)
    {
        if (!policy_downgrade_allowed())
        {
            mpss::utils::log_warning("MPSS_YUBIKEY_PINPOLICY=never ignored: set MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE "
                                     "to permanently disable PIN protection for newly created keys. Using 'once'.");
            return default_pin_policy;
        }
        mpss::utils::log_warning("MPSS_YUBIKEY_PINPOLICY=never permanently disables PIN protection for keys "
                                 "created now.");
        return YKPIV_PINPOLICY_NEVER;
    }
    if ("once" == value)
    {
        return YKPIV_PINPOLICY_ONCE;
    }
    if ("always" == value)
    {
        return YKPIV_PINPOLICY_ALWAYS;
    }
    mpss::utils::log_warning("MPSS_YUBIKEY_PINPOLICY has unrecognized value '{}'. "
                             "Expected: default, never, once, always. Defaulting to 'once'.",
                             env_ptr);
    return default_pin_policy;
}

/** @brief Read YubiKey touch policy from the MPSS_YUBIKEY_TOUCHPOLICY environment variable. */
std::uint8_t get_touch_policy_from_env()
{
    const char *env_ptr = std::getenv("MPSS_YUBIKEY_TOUCHPOLICY");
    if (nullptr == env_ptr)
    {
        mpss::utils::log_trace("MPSS_YUBIKEY_TOUCHPOLICY environment variable not set. Defaulting to 'cached' policy.");
        return default_touch_policy;
    }

    const std::string value = to_lower(env_ptr);
    if ("default" == value)
    {
        return YKPIV_TOUCHPOLICY_DEFAULT;
    }
    if ("never" == value)
    {
        if (!policy_downgrade_allowed())
        {
            mpss::utils::log_warning("MPSS_YUBIKEY_TOUCHPOLICY=never ignored: set MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE "
                                     "to permanently disable touch protection for newly created keys. Using 'cached'.");
            return default_touch_policy;
        }
        mpss::utils::log_warning("MPSS_YUBIKEY_TOUCHPOLICY=never permanently disables touch protection for keys "
                                 "created now.");
        return YKPIV_TOUCHPOLICY_NEVER;
    }
    if ("always" == value)
    {
        return YKPIV_TOUCHPOLICY_ALWAYS;
    }
    if ("cached" == value)
    {
        return YKPIV_TOUCHPOLICY_CACHED;
    }
    if ("auto" == value)
    {
        return YKPIV_TOUCHPOLICY_AUTO;
    }

    mpss::utils::log_warning("MPSS_YUBIKEY_TOUCHPOLICY has unrecognized value '{}'. "
                             "Expected: default, never, always, cached, auto. Defaulting to 'cached'.",
                             env_ptr);
    return default_touch_policy;
}

} // namespace

namespace mpss::impl::yubikey::utils
{

using enum mpss::Algorithm;

bool is_affirmative_environment_value(std::string_view value)
{
    const std::string normalized = to_lower(value);
    return "1" == normalized || "true" == normalized || "yes" == normalized || "on" == normalized;
}

std::optional<std::uint32_t> parse_serial(std::string_view serial)
{
    if (serial.empty() || max_serial_length < serial.size())
    {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    const auto [end, error] = std::from_chars(serial.data(), serial.data() + serial.size(), value);
    if (std::errc{} != error || end != serial.data() + serial.size() || 0 == value)
    {
        return std::nullopt;
    }
    return value;
}

std::optional<std::uint32_t> get_serial_from_env()
{
    const char *serial = std::getenv("MPSS_YUBIKEY_SERIAL");
    if (nullptr == serial)
    {
        return std::nullopt;
    }

    const std::optional<std::uint32_t> value = parse_serial(serial);
    if (!value)
    {
        mpss::utils::log_warning("MPSS_YUBIKEY_SERIAL is not a valid decimal serial number; ignoring the default.");
    }
    return value;
}

SecureByteVector get_mgm_key_from_env()
{
    const char *env_ptr = std::getenv("MPSS_YUBIKEY_MGM_KEY");
    if (nullptr == env_ptr)
    {
        mpss::utils::log_trace("MPSS_YUBIKEY_MGM_KEY environment variable not set.");
        return {};
    }

    // Use string_view to avoid copying the environment string.
    const std::string_view hex_str{env_ptr};

    // Validate length for AES-128 (32), AES-192/TDES (48), or AES-256 (64).
    const std::size_t len = hex_str.size();
    if (len != 32 && len != 48 && len != 64)
    {
        mpss::utils::log_warning("MPSS_YUBIKEY_MGM_KEY has invalid length ({}). Expected 32, 48, or 64 hex characters.",
                                 len);
        return {};
    }

    auto key_opt = mpss::utils::hex_string_to_bytes<SecureByteVector>(hex_str);
    if (!key_opt)
    {
        mpss::utils::log_warning("MPSS_YUBIKEY_MGM_KEY contains invalid hex characters.");
        return {};
    }

    // std::move is required here to extract from the optional without copying.
    return std::move(*key_opt);
}

std::uint8_t resolve_pin_policy(KeyPolicy policy)
{
    const std::uint64_t field = static_cast<std::uint64_t>(policy & yubikey_pin_mask);
    if (0 == field)
    {
        // No programmatic policy specified - fall back to env var / default.
        return get_pin_policy_from_env();
    }

    switch (field)
    {
    case 1:
        return YKPIV_PINPOLICY_NEVER;
    case 2:
        return YKPIV_PINPOLICY_ONCE;
    case 3:
        return YKPIV_PINPOLICY_ALWAYS;
    default:
        mpss::utils::log_warning("Unrecognized YubiKey PIN policy value {} in KeyPolicy. Defaulting to 'once'.", field);
        return default_pin_policy;
    }
}

std::uint8_t resolve_touch_policy(KeyPolicy policy)
{
    const std::uint64_t field = static_cast<std::uint64_t>(policy & yubikey_touch_mask) >> 4;
    if (0 == field)
    {
        // No programmatic policy specified - fall back to env var / default.
        return get_touch_policy_from_env();
    }

    switch (field)
    {
    case 1:
        return YKPIV_TOUCHPOLICY_NEVER;
    case 2:
        return YKPIV_TOUCHPOLICY_ALWAYS;
    case 3:
        return YKPIV_TOUCHPOLICY_CACHED;
    default:
        mpss::utils::log_warning("Unrecognized YubiKey touch policy value {} in KeyPolicy. Defaulting to 'cached'.",
                                 field);
        return default_touch_policy;
    }
}

std::uint8_t mpss_to_yk_algorithm(Algorithm algorithm)
{
    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        return YKPIV_ALGO_ECCP256;
    case ecdsa_secp384r1_sha384:
        return YKPIV_ALGO_ECCP384;
    case ecdsa_secp521r1_sha512:
        // YubiKey PIV does not support P-521.
        return 0;
    default:
        return 0;
    }
}

Algorithm yk_to_mpss_algorithm(std::uint8_t yk_algorithm)
{
    switch (yk_algorithm)
    {
    case YKPIV_ALGO_ECCP256:
        return ecdsa_secp256r1_sha256;
    case YKPIV_ALGO_ECCP384:
        return ecdsa_secp384r1_sha384;
    default:
        return unsupported;
    }
}

const char *get_group_name(Algorithm algorithm)
{
    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        return "P-256";
    case ecdsa_secp384r1_sha384:
        return "P-384";
    default:
        return nullptr;
    }
}

#define MPSS_YKPIV_SLOT_CASE(slot_const, friendly_name)                                                                \
    case YKPIV_KEY_##slot_const:                                                                                       \
        return friendly_name;

std::string_view get_slot_name(std::uint8_t slot)
{
    switch (slot)
    {
        MPSS_YKPIV_SLOT_CASE(AUTHENTICATION, "9A (Authentication)")
        MPSS_YKPIV_SLOT_CASE(CARDMGM, "9B (Card Management)")
        MPSS_YKPIV_SLOT_CASE(SIGNATURE, "9C (Digital Signature)")
        MPSS_YKPIV_SLOT_CASE(KEYMGM, "9D (Key Management)")
        MPSS_YKPIV_SLOT_CASE(CARDAUTH, "9E (Card Authentication)")
        MPSS_YKPIV_SLOT_CASE(ATTESTATION, "F9 (Attestation)")
        MPSS_YKPIV_SLOT_CASE(RETIRED1, "82 (Retired 1)")
        MPSS_YKPIV_SLOT_CASE(RETIRED2, "83 (Retired 2)")
        MPSS_YKPIV_SLOT_CASE(RETIRED3, "84 (Retired 3)")
        MPSS_YKPIV_SLOT_CASE(RETIRED4, "85 (Retired 4)")
        MPSS_YKPIV_SLOT_CASE(RETIRED5, "86 (Retired 5)")
        MPSS_YKPIV_SLOT_CASE(RETIRED6, "87 (Retired 6)")
        MPSS_YKPIV_SLOT_CASE(RETIRED7, "88 (Retired 7)")
        MPSS_YKPIV_SLOT_CASE(RETIRED8, "89 (Retired 8)")
        MPSS_YKPIV_SLOT_CASE(RETIRED9, "8A (Retired 9)")
        MPSS_YKPIV_SLOT_CASE(RETIRED10, "8B (Retired 10)")
        MPSS_YKPIV_SLOT_CASE(RETIRED11, "8C (Retired 11)")
        MPSS_YKPIV_SLOT_CASE(RETIRED12, "8D (Retired 12)")
        MPSS_YKPIV_SLOT_CASE(RETIRED13, "8E (Retired 13)")
        MPSS_YKPIV_SLOT_CASE(RETIRED14, "8F (Retired 14)")
        MPSS_YKPIV_SLOT_CASE(RETIRED15, "90 (Retired 15)")
        MPSS_YKPIV_SLOT_CASE(RETIRED16, "91 (Retired 16)")
        MPSS_YKPIV_SLOT_CASE(RETIRED17, "92 (Retired 17)")
        MPSS_YKPIV_SLOT_CASE(RETIRED18, "93 (Retired 18)")
        MPSS_YKPIV_SLOT_CASE(RETIRED19, "94 (Retired 19)")
        MPSS_YKPIV_SLOT_CASE(RETIRED20, "95 (Retired 20)")
    default:
        return "Unknown Slot";
    }
}

} // namespace mpss::impl::yubikey::utils
