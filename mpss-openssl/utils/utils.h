// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <memory>
#include <mpss/mpss.h>
#include <openssl/types.h>
#include <span>
#include <utility>
#include <vector>

namespace mpss_openssl::utils
{

using byte_vector = std::vector<std::byte>;

template <typename T, typename... Args> [[nodiscard]] inline T *mpss_new(Args &&...args)
{
    return new T{std::forward<Args>(args)...}; // NOLINT(cppcoreguidelines-owning-memory)
}

template <typename T> inline void mpss_delete(T *obj)
{
    delete obj; // NOLINT(cppcoreguidelines-owning-memory)
}

std::size_t mpss_sign_as_der(const std::unique_ptr<mpss::KeyPair> &key_pair, std::span<const std::byte> hash_tbs,
                             std::span<std::byte> out);

[[nodiscard]] bool verify_der(const std::unique_ptr<mpss::KeyPair> &key_pair, std::span<const std::byte> hash_tbs,
                              std::span<const std::byte> der_sig);

[[nodiscard]] byte_vector mpss_vk_params_to_spki(OSSL_LIB_CTX *libctx, const OSSL_PARAM *params);

} // namespace mpss_openssl::utils
