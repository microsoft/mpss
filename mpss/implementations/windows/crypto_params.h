// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <Windows.h>
#include <ncrypt.h>

namespace mpss::impl {
	// Abstract property class for crypto parameters
	class crypto_params {
	public:
		// Signing key type identifier
		virtual LPCWSTR key_type_name() const = 0;

		// Key blob type
		using key_blob_t = BCRYPT_ECCKEY_BLOB;

		// Public key blob type identifier
		virtual LPCWSTR public_key_blob_name() const = 0;

		// Private key blob type identifier
		virtual LPCWSTR private_key_blob_name() const = 0;

		// Public key magic value
		virtual DWORD public_key_magic() const = 0;

		// Private key magic value
		virtual DWORD private_key_magic() const = 0;
	};

#define MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(curve) \
    class ECDSA_##curve## : public crypto_params { \
    public: \
        LPCWSTR key_type_name() const override { return NCRYPT_ECDSA_##curve##_ALGORITHM; }; \
        LPCWSTR public_key_blob_name() const override { return BCRYPT_ECCPUBLIC_BLOB; } \
        LPCWSTR private_key_blob_name() const override { return BCRYPT_ECCPRIVATE_BLOB; } \
        DWORD public_key_magic() const override { return BCRYPT_ECDSA_PUBLIC_##curve##_MAGIC; } \
        DWORD private_key_magic() const override { return BCRYPT_ECDSA_PRIVATE_##curve##_MAGIC; } \
    };

	// For now, provide three concrete implementations.
	MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(P256)
	MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(P384)
	MPSS_IMPL_WINDOWS_CRYPTO_PARAMS(P521)
}
