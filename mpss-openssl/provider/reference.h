// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/utils.h"
#include "mpss/impl/serialization.h"
#include "mpss/mpss.h"
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace mpss_openssl::provider
{

inline constexpr const char *mpss_key_reference_pem_label = mpss::impl::key_reference_pem_label;
inline constexpr std::size_t mpss_max_reference_size = mpss::impl::max_reference_size;
inline constexpr std::size_t mpss_max_reference_pem_size = mpss::impl::max_reference_pem_size;

// Persisted DER: SEQUENCE { version INTEGER, backend UTF8String, name UTF8String,
//                          device [0] EXPLICIT UTF8String OPTIONAL, publicKey SubjectPublicKeyInfo }.
// Internal store requests use a separate [0]-tagged ASN.1 structure and cannot be loaded as PEM.
enum class mpss_reference_kind : std::uint8_t
{
    locator,        // Internal store request with explicit selection; absent device means automatic.
    bound,          // Persisted location and expected public key.
    default_locator // Internal store request using backend/environment defaults.
};

struct mpss_load_reference
{
    mpss::KeyReference key{};
    mpss_reference_kind kind = mpss_reference_kind::locator;
};

using mpss_reference_error = mpss::impl::ReferenceError;

// Internal store requests may use defaults or an explicit location; neither form is a PEM reference.
[[nodiscard]]
bool mpss_build_key_load_reference(std::string_view backend, std::string_view key_name, utils::byte_vector &reference);

[[nodiscard]]
bool mpss_build_key_load_reference(const mpss::KeyLocation &location, utils::byte_vector &reference);

[[nodiscard]]
bool mpss_parse_key_load_reference(std::span<const unsigned char> reference, mpss_load_reference &parsed,
                                   mpss_reference_error &error);

} // namespace mpss_openssl::provider
