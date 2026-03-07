// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include <cstdint>

namespace mpss
{

/**
 * @brief Policy flags for key creation.
 *
 * KeyPolicy is a bitmask of packed multi-bit fields. Each field encodes a single policy aspect
 * (e.g., YubiKey PIN policy, YubiKey touch policy). Within each field, zero means "unset" - the
 * backend falls back to environment variables or its hardcoded default.
 *
 * Bit layout:
 * - Bits 0–3:  YubiKey PIN policy (4-bit field).
 * - Bits 4–7:  YubiKey touch policy (4-bit field).
 * - Bits 8–63: Reserved for other backends.
 */
enum class MPSS_DECOR KeyPolicy : std::uint64_t
{
    /** @brief No policy specified. All fields fall back to env var / backend defaults. */
    none = 0,

#ifdef MPSS_BACKEND_YUBIKEY
    // -- YubiKey PIN policy (bits 0–3). Zero = use env var / MPSS default. --

    /** @brief Never require PIN for signing. */
    yubikey_pin_never = 1U,
    /** @brief Require PIN once per PIV session. */
    yubikey_pin_once = 2U,
    /** @brief Require PIN for every signing operation. */
    yubikey_pin_always = 3U,
    // Values 4–15 reserved (match_once, match_always pending biometric InteractionHandler support).

    // -- YubiKey touch policy (bits 4–7). Zero = use env var / MPSS default. --

    /** @brief Never require physical touch for signing. */
    yubikey_touch_never = 1U << 4U,
    /** @brief Require physical touch for every signing operation. */
    yubikey_touch_always = 2U << 4U,
    /** @brief Require physical touch once per 15-second window. */
    yubikey_touch_cached = 3U << 4U,
    // Values 4–15 reserved (auto, future policies).
#endif // MPSS_BACKEND_YUBIKEY
};

#ifdef MPSS_BACKEND_YUBIKEY

/** @brief Group mask for YubiKey PIN policy (bits 0–3). */
inline constexpr KeyPolicy yubikey_pin_mask = KeyPolicy{0xFU};

/** @brief Group mask for YubiKey touch policy (bits 4–7). */
inline constexpr KeyPolicy yubikey_touch_mask = KeyPolicy{0xFU << 4U};

#endif // MPSS_BACKEND_YUBIKEY

/** @brief Bitwise OR for combining policy fields. */
constexpr KeyPolicy operator|(KeyPolicy a, KeyPolicy b) noexcept
{
    return static_cast<KeyPolicy>(static_cast<std::uint64_t>(a) | static_cast<std::uint64_t>(b));
}

/** @brief Bitwise AND for extracting policy fields. */
constexpr KeyPolicy operator&(KeyPolicy a, KeyPolicy b) noexcept
{
    return static_cast<KeyPolicy>(static_cast<std::uint64_t>(a) & static_cast<std::uint64_t>(b));
}

/** @brief Bitwise NOT. */
constexpr KeyPolicy operator~(KeyPolicy a) noexcept
{
    return static_cast<KeyPolicy>(~static_cast<std::uint64_t>(a));
}

/** @brief Bitwise OR assignment. */
constexpr KeyPolicy &operator|=(KeyPolicy &a, KeyPolicy b) noexcept
{
    a = a | b;
    return a;
}

/** @brief Bitwise AND assignment. */
constexpr KeyPolicy &operator&=(KeyPolicy &a, KeyPolicy b) noexcept
{
    a = a & b;
    return a;
}

} // namespace mpss
