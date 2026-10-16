// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <Windows.h>
#include <ncrypt.h>

namespace mpss::impl::os
{

// Abstract property struct for crypto parameters.
struct crypto_params
{
    // Signing key type identifier.
    [[nodiscard]]
    virtual LPCWSTR key_type_name() const = 0;

    // Key blob type.
    using key_blob_t = BCRYPT_ECCKEY_BLOB;

    // Public key blob type identifier.
    [[nodiscard]]
    virtual LPCWSTR public_key_blob_name() const = 0;

    // Private key blob type identifier.
    [[nodiscard]]
    virtual LPCWSTR private_key_blob_name() const = 0;

    // Public key magic value.
    [[nodiscard]]
    virtual DWORD public_key_magic() const = 0;
};

#define MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(group)                                                                         \
    struct ECDSA_##group : public crypto_params                                                                        \
    {                                                                                                                  \
        LPCWSTR key_type_name() const override                                                                         \
        {                                                                                                              \
            return NCRYPT_ECDSA_##group##_ALGORITHM;                                                                   \
        };                                                                                                             \
        LPCWSTR public_key_blob_name() const override                                                                  \
        {                                                                                                              \
            return BCRYPT_ECCPUBLIC_BLOB;                                                                              \
        }                                                                                                              \
        LPCWSTR private_key_blob_name() const override                                                                 \
        {                                                                                                              \
            return BCRYPT_ECCPRIVATE_BLOB;                                                                             \
        }                                                                                                              \
        DWORD public_key_magic() const override                                                                        \
        {                                                                                                              \
            return BCRYPT_ECDSA_PUBLIC_##group##_MAGIC;                                                                \
        }                                                                                                              \
    };

// For now, provide three concrete implementations.
MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(P256)
MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(P384)
MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(P521)

} // namespace mpss::impl::os
