// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/mpss_impl.h"
#include "mpss/implementations/windows/p256.h"
#include "mpss/implementations/windows/p384.h"
#include "mpss/implementations/windows/p521.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"

#include <sstream>
#include <utility>

#include <windows.h>
#include <ncrypt.h>

namespace {
    using namespace mpss::impl;

    // Error code of the last error that occurred.
    thread_local SECURITY_STATUS last_error = ERROR_SUCCESS;

    // Legacy key spec. We only store signing keys.
    constexpr DWORD key_spec = AT_SIGNATURE;

    // Choose the provider name. To use TPM, use MS_PLATFORM_KEY_STORAGE_PROVIDER.
    // To use software provider, use MS_KEY_STORAGE_PROVIDER instead.
    constexpr LPCWSTR provider_name = MS_KEY_STORAGE_PROVIDER;

    // To open the key for the local machine, set this to NCRYPT_MACHINE_KEY_FLAG.
    // Setting this to 0 opens the key for the current user.
    constexpr DWORD key_open_mode = 0;

    // Namespace alias to choose the crypto parameters.
#if   MPSS_CRYPTO_PARAMS == P256
    namespace crypto = p256;
#elif MPSS_CRYPTO_PARAMS == P384
    namespace crypto = p384;
#elif MPSS_CRYPTO_PARAMS == P521
    namespace crypto = p521;
#else
#error "Unsupported MPSS_CRYPTO_PARAMS value"
#endif

    void set_error(SECURITY_STATUS status, std::string error)
    {
        last_error = status;
        mpss::utils::set_error(std::move(error));
    }

    NCRYPT_PROV_HANDLE GetProvider()
    {
        NCRYPT_PROV_HANDLE provider_handle = 0;

        // This function uses no extra flags.
        DWORD flags = 0;

        SECURITY_STATUS status = ::NCryptOpenStorageProvider(&provider_handle, provider_name, flags);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenStorageProvider failed with error code " << mpss::utils::to_hex(status);
            set_error(status, ss.str());
            return 0;
        }

        return provider_handle;
    }

    NCRYPT_KEY_HANDLE GetKey(std::string_view name)
    {
        NCRYPT_PROV_HANDLE provider_handle = GetProvider();
        if (!provider_handle) {
            return 0;
        }

        SCOPE_GUARD(::NCryptFreeObject(provider_handle));

        NCRYPT_KEY_HANDLE key_handle = 0;
        std::wstring wname(name.begin(), name.end());

        SECURITY_STATUS status = ::NCryptOpenKey(provider_handle, &key_handle, wname.c_str(), key_spec, key_open_mode);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenKey failed with error code " << mpss::utils::to_hex(status);
            set_error(status, ss.str());
            return 0;
        }

        return key_handle;
    }
}

namespace mpss
{
    namespace impl
    {
        int create_key(std::string_view name)
        {
            NCRYPT_PROV_HANDLE provider_handle = GetProvider();
            if (!provider_handle) {
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(provider_handle));

            NCRYPT_KEY_HANDLE key_handle = 0;
            std::wstring wname(name.begin(), name.end());

            SECURITY_STATUS status = ::NCryptCreatePersistedKey(
                provider_handle,
                &key_handle,
                crypto::key_type_name,
                wname.c_str(),
                key_spec,
                key_open_mode);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptCreatePersistedKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            // Set the export policy to allow exporting the key.
            DWORD export_policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            status = ::NCryptSetProperty(
                key_handle,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                reinterpret_cast<PBYTE>(&export_policy),
                sizeof(export_policy),
                NCRYPT_PERSIST_FLAG);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSetProperty failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            status = ::NCryptFinalizeKey(key_handle, /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptFinalizeKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            return 0;
        }

        int delete_key(std::string_view name)
        {
            NCRYPT_KEY_HANDLE key_handle = GetKey(name);
            if (!key_handle) {
                // If the key does not exist, consider it deleted.
                if (NTE_BAD_KEYSET == last_error) {
                    return 0;
                }
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(key_handle));

            SECURITY_STATUS status = ::NCryptDeleteKey(key_handle, /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptDeleteKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            return 0;
        }

        std::string sign(std::string_view name, std::string data)
        {
            std::string signature;
            NCRYPT_KEY_HANDLE key_handle = GetKey(name);
            if (!key_handle) {
                return signature;
            }

            SCOPE_GUARD(::NCryptFreeObject(key_handle));

            DWORD signature_size = 0;

            // Get signature size.
            SECURITY_STATUS status = ::NCryptSignHash(
                key_handle,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<BYTE*>(data.data()),
                static_cast<DWORD>(data.size()),
                nullptr,
                0,
                &signature_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSignHash failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return signature;
            }

            // Get the actual signature.
            signature.resize(signature_size);
            status = ::NCryptSignHash(
                key_handle,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<BYTE*>(const_cast<char*>(data.data())),
                static_cast<DWORD>(data.size()),
                reinterpret_cast<PBYTE>(&signature[0]),
                static_cast<DWORD>(signature.size()),
                &signature_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSignHash failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return std::string();
            }

            return signature;
        }

        int verify(std::string_view name, std::string data, std::string signature)
        {
            NCRYPT_KEY_HANDLE key_handle = GetKey(name);
            if (!key_handle) {
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(key_handle));

            SECURITY_STATUS status = ::NCryptVerifySignature(
                key_handle,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<BYTE*>(data.data()),
                static_cast<DWORD>(data.size()),
                reinterpret_cast<BYTE*>(signature.data()),
                static_cast<DWORD>(signature.size()),
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptVerifySignature failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            return 0;
        }

        int get_key(std::string_view name, std::string& vk_out, std::string& sk_out)
        {
            NCRYPT_KEY_HANDLE key_handle = GetKey(name);
            if (!key_handle) {
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(key_handle));

            // Get the public key size.
            DWORD public_key_size = 0;
            SECURITY_STATUS status = ::NCryptExportKey(
                key_handle,
                /* hExportKey */ 0,
                crypto::public_key_blob_name,
                /* pParameterList */ nullptr,
                /* pbOutput */ nullptr,
                /* cbOutput */ 0,
                &public_key_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            // Actually get the public key
            BYTE* public_key_ptr = new BYTE[public_key_size];
            SCOPE_GUARD(delete[] public_key_ptr);

            status = ::NCryptExportKey(
                key_handle,
                /* hExportKey */ 0,
                crypto::public_key_blob_name,
                /* pParameterList */ nullptr,
                public_key_ptr,
                public_key_size,
                &public_key_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            crypto::key_blob_t* public_key_blob_ptr = reinterpret_cast<crypto::key_blob_t*>(public_key_ptr);
            if (public_key_blob_ptr->dwMagic != crypto::public_key_magic) {
                set_error(status, "Invalid public key magic");
                return -1;
            }

            BYTE* data_start_ptr = reinterpret_cast<BYTE*>(public_key_blob_ptr) + sizeof(crypto::key_blob_t);
            vk_out.assign(reinterpret_cast<char*>(data_start_ptr), public_key_size - sizeof(crypto::key_blob_t));

            // Get the private key size.
            DWORD private_key_size = 0;
            status = ::NCryptExportKey(
                key_handle,
                /* hExportKey */ 0,
                crypto::private_key_blob_name,
                /* pParameterList */ nullptr,
                /* pbOutput */ nullptr,
                /* cbOutput */ 0,
                &private_key_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            // Actually get the private key
            BYTE* private_key_ptr = new BYTE[private_key_size];
            SCOPE_GUARD(delete[] private_key_ptr);

            status = ::NCryptExportKey(
                key_handle,
                /* hExportKey */ 0,
                crypto::private_key_blob_name,
                /* pParameterList */ nullptr,
                private_key_ptr,
                private_key_size,
                &private_key_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            crypto::key_blob_t* private_key_blob_ptr = reinterpret_cast<crypto::key_blob_t*>(private_key_ptr);
            if (private_key_blob_ptr->dwMagic != crypto::private_key_magic) {
                set_error(status, "Invalid private key magic");
                return -1;
            }

            data_start_ptr = reinterpret_cast<BYTE*>(private_key_blob_ptr) + sizeof(crypto::key_blob_t);
            sk_out.assign(reinterpret_cast<char*>(data_start_ptr), private_key_size - sizeof(crypto::key_blob_t));

            return 0;
        }

        std::string get_error()
        {
            return mpss::utils::get_error();
        }
    }
}
