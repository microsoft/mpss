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
 * @brief Return the generation recorded for this key name.
 *
 * A generation is a number used to detect deletion of a key with this name.
 * Creating or opening a handle saves the current number. Deletion through MPSS assigns
 * a new one; a handle whose saved number no longer matches refuses key operations.
 * Closing and reopening without deleting the key does not change the number.
 *
 * Apple and Android use generations to identify cache entries instead: a new entry gets a
 * new number, including when the same stored key is reopened after its last handle closes.
 *
 * This function's mutex protects only the generation map, not the Windows key operation.
 * KeyPair::Create, KeyPair::Open, KeyPair::Delete and deletion through a handle use
 * name_mutex(name) to prevent those operations from overlapping for the same name.
 *
 * Only deletions performed by this MPSS process are tracked.
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
