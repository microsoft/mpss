// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include "crypto_params.h"

namespace mpss::impl {
    class ecdsa_p384 : public crypto_params {
    public:
        // Signing key type identifier.
        virtual LPCWSTR get_key_type_name() const override {
            return NCRYPT_ECDSA_P384_ALGORITHM;
        };

        // Public key blob type identifier.
        virtual LPCWSTR get_public_key_blob_name() const override {
            return BCRYPT_ECCPUBLIC_BLOB;
        }

        // Private key blob type identifier.
        virtual LPCWSTR get_private_key_blob_name() const override {
            return BCRYPT_ECCPRIVATE_BLOB;
        }

        // Public key magic value.
        virtual DWORD get_public_key_magic() const override {
            return BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        }

        // Private key magic value.
        virtual DWORD get_private_key_magic() const override {
            return BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        }
    };
}
