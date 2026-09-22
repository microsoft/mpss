// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include "mpss/key_reference.h"
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifdef MPSS_WITH_SERIALIZATION
namespace mpss
{

/**
 * @brief Encodes a key reference as versioned ASN.1 DER, without accessing a backend.
 *
 * Validates the location's syntax, algorithm and public key; it does not establish trust,
 * check backend availability, or resolve environment defaults. Returns nullopt on failure
 * and reports the error through get_error().
 */
[[nodiscard]]
MPSS_DECOR std::optional<std::vector<std::byte>> encode_key_reference_der(const KeyReference &reference);

/**
 * @brief Decodes exactly one canonical DER reference, without opening a key.
 *
 * Accepts at most 4096 bytes. Rejects unsupported versions, malformed or invalid public keys,
 * and trailing data. The returned reference owns its data; use KeyPair::Open to resolve it.
 * Returns nullopt on failure and reports the error through get_error().
 */
[[nodiscard]]
MPSS_DECOR std::optional<KeyReference> decode_key_reference_der(std::span<const std::byte> der);

/** @brief Encodes the same DER reference as an MPSS KEY REFERENCE PEM, with LF line endings. */
[[nodiscard]]
MPSS_DECOR std::optional<std::string> encode_key_reference_pem(const KeyReference &reference);

/**
 * @brief Decodes one MPSS KEY REFERENCE PEM, with optional surrounding ASCII whitespace.
 *
 * Accepts at most 8192 bytes, including whitespace. No backend access or private-key operation.
 * Returns nullopt on failure and reports the error through get_error().
 */
[[nodiscard]]
MPSS_DECOR std::optional<KeyReference> decode_key_reference_pem(std::string_view pem);

} // namespace mpss
#endif
