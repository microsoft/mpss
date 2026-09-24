// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/serialization.h"

namespace mpss::impl
{

inline constexpr const char *key_reference_pem_label = "MPSS KEY REFERENCE";
inline constexpr std::size_t max_reference_size = 4096;
inline constexpr std::size_t max_reference_pem_size = 8192;

enum class ReferenceError
{
    malformed,
    unsupported
};

// Preserve structured diagnostics for the provider's OpenSSL error channel. These entry points are
// internal to MPSS and its provider; the header is not installed.
[[nodiscard]]
MPSS_DECOR std::optional<KeyReference> decode_key_reference_der(std::span<const std::byte> der, ReferenceError &error);

[[nodiscard]]
MPSS_DECOR std::optional<KeyReference> decode_key_reference_pem(std::string_view pem, ReferenceError &error);

} // namespace mpss::impl
