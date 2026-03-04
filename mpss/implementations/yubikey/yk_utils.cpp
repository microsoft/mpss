// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/yubikey/yk_utils.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <format>
#include <limits>
#include <ykpiv/ykpiv.h>

namespace
{

/** @brief Convert a string to lowercase. */
std::string to_lower(std::string_view str)
{
    std::string result{str};
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

} // namespace

namespace mpss::impl::yubikey::utils
{

using enum mpss::Algorithm;

std::optional<std::uint32_t> get_serial_from_env()
{
    const char *serial = std::getenv("MPSS_YUBIKEY_SERIAL");
    if (nullptr == serial)
    {
        return std::nullopt;
    }

    char *end = nullptr;
    const unsigned long value = std::strtoul(serial, &end, 10);
    if (end == serial || *end != '\0' || 0 == value)
    {
        mpss::utils::log_warn("MPSS_YUBIKEY_SERIAL value '{}' is not a valid serial number.", serial);
        return std::nullopt;
    }

    if (value > std::numeric_limits<std::uint32_t>::max())
    {
        mpss::utils::log_warn("MPSS_YUBIKEY_SERIAL value '{}' is out of range.", serial);
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(value);
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
        mpss::utils::log_warn("MPSS_YUBIKEY_MGM_KEY has invalid length ({}). Expected 32, 48, or 64 hex characters.",
                              len);
        return {};
    }

    auto key_opt = mpss::utils::hex_string_to_bytes<SecureByteVector>(hex_str);
    if (!key_opt)
    {
        mpss::utils::log_warn("MPSS_YUBIKEY_MGM_KEY contains invalid hex characters.");
        return {};
    }

    // std::move is required here to extract from the optional without copying.
    return std::move(*key_opt);
}

std::uint8_t get_pin_policy_from_env()
{
    const char *env_ptr = std::getenv("MPSS_YUBIKEY_PINPOLICY");
    if (nullptr == env_ptr)
    {
        mpss::utils::log_trace("MPSS_YUBIKEY_PINPOLICY environment variable not set. Defaulting to 'once' policy.");
        return YKPIV_PINPOLICY_ONCE;
    }

    const std::string value = to_lower(env_ptr);
    if ("default" == value)
    {
        return YKPIV_PINPOLICY_DEFAULT;
    }
    if ("never" == value)
    {
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
    if ("match_once" == value)
    {
        return YKPIV_PINPOLICY_MATCH_ONCE;
    }
    if ("match_always" == value)
    {
        return YKPIV_PINPOLICY_MATCH_ALWAYS;
    }

    mpss::utils::log_warn("MPSS_YUBIKEY_PINPOLICY has unrecognized value '{}'. "
                          "Expected: default, never, once, always, match_once, match_always. Defaulting to 'once'.",
                          env_ptr);
    return YKPIV_PINPOLICY_ONCE;
}

std::uint8_t get_touch_policy_from_env()
{
    const char *env_ptr = std::getenv("MPSS_YUBIKEY_TOUCHPOLICY");
    if (nullptr == env_ptr)
    {
        mpss::utils::log_trace("MPSS_YUBIKEY_TOUCHPOLICY environment variable not set. Defaulting to 'never' policy.");
        return YKPIV_TOUCHPOLICY_NEVER;
    }

    const std::string value = to_lower(env_ptr);
    if ("default" == value)
    {
        return YKPIV_TOUCHPOLICY_DEFAULT;
    }
    if ("never" == value)
    {
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

    mpss::utils::log_warn("MPSS_YUBIKEY_TOUCHPOLICY has unrecognized value '{}'. "
                          "Expected: default, never, always, cached, auto. Defaulting to 'never'.",
                          env_ptr);
    return YKPIV_TOUCHPOLICY_NEVER;
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
