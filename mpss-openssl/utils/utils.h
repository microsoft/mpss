// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <memory>
#include <mpss/mpss.h>
#include <openssl/types.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace mpss_openssl::utils
{

using byte_vector = std::vector<std::byte>;

/**
 * @brief Deleter that releases an object with a compile-time known function.
 *
 * @p Fn is a template parameter rather than a stored function pointer, so the deleter is an empty
 * class and a `std::unique_ptr` using it stays the size of a raw pointer.
 */
template <auto Fn> struct fn_deleter
{
    template <typename T> void operator()(T *ptr) const noexcept
    {
        Fn(ptr);
    }
};

template <typename T, typename... Args>
[[nodiscard]]
inline T *mpss_new(Args &&...args)
{
    return new T{std::forward<Args>(args)...}; // NOLINT(cppcoreguidelines-owning-memory)
}

template <typename T> inline void mpss_delete(T *obj)
{
    delete obj; // NOLINT(cppcoreguidelines-owning-memory)
}

/**
 * @brief Owns a provider struct until OpenSSL takes it.
 *
 * Call `release()` where ownership passes to the caller; anything else releases with
 * @ref mpss_delete.
 */
template <typename T> using mpss_ptr = std::unique_ptr<T, fn_deleter<mpss_delete<T>>>;

std::size_t mpss_sign_as_der(const std::unique_ptr<mpss::KeyPair> &key_pair, std::span<const std::byte> hash_tbs,
                             std::span<std::byte> out);

[[nodiscard]]
bool verify_der(const std::unique_ptr<mpss::KeyPair> &key_pair, std::span<const std::byte> hash_tbs,
                std::span<const std::byte> der_sig);

[[nodiscard]]
byte_vector mpss_vk_params_to_spki(OSSL_LIB_CTX *libctx, const OSSL_PARAM *params);

// Clear every key stored under the name, in the default backend or in backend_name. Returns false
// only when the storage could not be cleared; a name that holds nothing already succeeds.
[[nodiscard]]
bool delete_key(std::string_view name);

[[nodiscard]]
bool delete_key(std::string_view name, std::string_view backend_name);

} // namespace mpss_openssl::utils
