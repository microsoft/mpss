// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/windows/crypto_params.h"
#include "mpss/mpss.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace mpss::impl::os::utils
{

crypto_params const *get_crypto_params(Algorithm algorithm) noexcept;

/** @brief The generation returned when this process has not deleted a key with this name. */
inline constexpr std::uint64_t never_deleted_generation = 0;

/**
 * @brief Returns the generation recorded for this key name.
 *
 * Creating or opening a handle records the current generation. Deleting through MPSS assigns a
 * new one, so a handle whose recorded generation no longer matches refuses key operations. Closing
 * and reopening without deleting does not change it, and only deletions made by this process are
 * seen. The mutex here protects only the map; the per-name lifecycle lock keeps a read from
 * overlapping a deletion of the same name.
 *
 * @param name The key name to read.
 * @return The recorded generation, or @ref never_deleted_generation if no deletion is recorded.
 */
[[nodiscard]]
std::uint64_t current_key_generation(std::string_view name);

/**
 * @brief Assign a new generation to this name so existing handles fail their generation checks.
 *
 * @param name The name of the deleted key.
 */
void invalidate_key_generation(std::string_view name);

// Converts a wide string from a Windows API to UTF-8 so it can be logged. Returns an empty string
// when the input is empty or cannot be converted.
[[nodiscard]]
std::string wide_to_utf8(std::wstring_view value);

std::size_t decode_raw_signature(std::span<const std::byte> der_sig, Algorithm algorithm,
                                 std::span<std::byte> raw_sig) noexcept;

} // namespace mpss::impl::os::utils
