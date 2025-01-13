// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <windows.h>
#include <ncrypt.h>

namespace mpss::impl::ecdsa_p256 {
    // Signing key type identifier.
    constexpr LPCWSTR key_type_name = NCRYPT_ECDSA_P256_ALGORITHM;

    // Key blob type.
    using key_blob_t = BCRYPT_ECCKEY_BLOB;

    // Public key blob type identifier.
    constexpr LPCWSTR public_key_blob_name = BCRYPT_ECCPUBLIC_BLOB;

    // Private key blob type identifier.
    constexpr LPCWSTR private_key_blob_name = BCRYPT_ECCPRIVATE_BLOB;

    // Public key magic value.
    constexpr DWORD public_key_magic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;

    // Private key magic value.
    constexpr DWORD private_key_magic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
}