// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <windows.h>
#include <ncrypt.h>

namespace mpss::impl {
	// Abstract property class for crypto parameters
	class crypto_params {
	public:
		// Signing key type identifier
		virtual LPCWSTR get_key_type_name() const = 0;

		// Key blob type
		using key_blob_t = BCRYPT_ECCKEY_BLOB;

		// Public key blob type identifier
		virtual LPCWSTR get_public_key_blob_name() const = 0;

		// Private key blob type identifier
		virtual LPCWSTR get_private_key_blob_name() const = 0;

		// Public key magic value
		virtual DWORD get_public_key_magic() const = 0;

		// Private key magic value
		virtual DWORD get_private_key_magic() const = 0;
	};
}
