// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/memory.h"
#include "mpss-openssl/utils/names.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <mpss/mpss.h>

#include <gsl/span>

namespace mpss_openssl::utils {
    std::size_t mpss_sign_as_der(const std::unique_ptr<mpss::KeyPair>& key_pair, gsl::span<const std::byte> hash_tbs, gsl::span<std::byte> out);

    [[nodiscard]] bool verify_der(const std::unique_ptr<mpss::KeyPair>& key_pair, gsl::span<const std::byte> hash_tbs, gsl::span<const std::byte> der_sig);

    [[nodiscard]] common_byte_vector mpss_vk_params_to_spki(OSSL_LIB_CTX* libctx, const OSSL_PARAM* params);

    [[nodiscard]] std::string_view get_canonical_hash_name(std::string_view name);
    [[nodiscard]] std::string_view get_canonical_sig_name(std::string_view name);
    [[nodiscard]] std::string_view get_canonical_group_name(std::string_view name);
    [[nodiscard]] std::string_view get_canonical_algorithm_name(std::string_view name);

    [[nodiscard]] bool are_same_hash(std::string_view name1, std::string_view name2);
    [[nodiscard]] bool are_same_sig(std::string_view name1, std::string_view name2);
    [[nodiscard]] bool are_same_group(std::string_view name1, std::string_view name2);

    [[nodiscard]] std::optional<std::string> try_get_ec_group(const std::unique_ptr<mpss::KeyPair>& key_pair);
    [[nodiscard]] std::optional<std::string> try_get_hash_func(const std::unique_ptr<mpss::KeyPair>& key_pair);
    [[nodiscard]] std::optional<std::string> try_get_signature_scheme(const std::unique_ptr<mpss::KeyPair>& key_pair);
    [[nodiscard]] std::optional<std::string> try_get_algorithm_name(const std::unique_ptr<mpss::KeyPair>& key_pair);
}