// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/types.h>
#include <array>
#include <memory>
#include <mpss/mpss.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mpss_openssl::utils {
    using byte_vector = std::vector<std::byte>;

    inline constexpr const char *ec_encoder_names = "EC";

    inline constexpr const char *ec_key_names = "EC:id_ecPublicKey:1.2.840.10045.2.1";

    inline constexpr std::array<const char *, 3> mpss_hash_names = {
        OSSL_DIGEST_NAME_SHA2_256 ":SHA256:SHA2-256:SHA-2-256:sha256:sha2-256:sha-2-256",
        OSSL_DIGEST_NAME_SHA2_384 ":SHA384:SHA2-384:SHA-2-384:sha384:sha2-384:sha-2-384",
        OSSL_DIGEST_NAME_SHA2_512 ":SHA512:SHA2-512:SHA-2-512:sha512:sha2-512:sha-2-512"};

    inline constexpr std::size_t SHA256_index = 0;
    inline constexpr std::size_t SHA384_index = 1;
    inline constexpr std::size_t SHA512_index = 2;

    inline constexpr std::array<const char *, 1> mpss_sig_names = {"ECDSA:ecdsa"};

    inline constexpr std::size_t ECDSA_index = 0;

    inline constexpr std::array<const char *, 3> mpss_group_names = {
        SN_X9_62_prime256v1 ":secp256r1:prime256v1:p256:p-256:P256:P-256",
        SN_secp384r1 ":secp384r1:prime384v1:p384:p-384:P384:P-384",
        SN_secp521r1 ":secp521r1:prime521v1:p521:p-521:P521:P-521",
    };

    inline constexpr std::array<const char *, 3> mpss_algorithm_names = {
        SN_ecdsa_with_SHA256, SN_ecdsa_with_SHA384, SN_ecdsa_with_SHA512};

    [[nodiscard]] std::string_view get_canonical_hash_name(std::string_view name);
    [[nodiscard]] std::string_view get_canonical_sig_name(std::string_view name);
    [[nodiscard]] std::string_view get_canonical_group_name(std::string_view name);
    [[nodiscard]] std::string_view get_canonical_algorithm_name(std::string_view name);

    [[nodiscard]] bool are_same_hash(std::string_view name1, std::string_view name2);
    [[nodiscard]] bool are_same_sig(std::string_view name1, std::string_view name2);
    [[nodiscard]] bool are_same_group(std::string_view name1, std::string_view name2);

    [[nodiscard]] std::optional<std::string> try_get_ec_group(const std::unique_ptr<mpss::KeyPair> &key_pair);
    [[nodiscard]] std::optional<std::string> try_get_hash_func(const std::unique_ptr<mpss::KeyPair> &key_pair);
    [[nodiscard]] std::optional<std::string> try_get_signature_scheme(const std::unique_ptr<mpss::KeyPair> &key_pair);
    [[nodiscard]] std::optional<std::string> try_get_algorithm_name(const std::unique_ptr<mpss::KeyPair> &key_pair);
    [[nodiscard]] mpss::Algorithm try_get_mpss_algorithm(std::string_view str);
} // namespace mpss_openssl::utils