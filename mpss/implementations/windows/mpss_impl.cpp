// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/mpss_impl.h"
#include "mpss/implementations/windows/ecdsa_p256.h"
#include "mpss/implementations/windows/ecdsa_p384.h"
#include "mpss/implementations/windows/ecdsa_p521.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"

#include <sstream>
#include <utility>
#include <string>
#include <locale>
#include <codecvt>

#include <windows.h>
#include <ncrypt.h>

namespace {
    using namespace mpss::impl;

    // Error code of the last error that occurred.
    thread_local SECURITY_STATUS last_error = ERROR_SUCCESS;

    // Legacy key spec. We only store signing keys.
    constexpr DWORD key_spec = 0;

    // Choose the provider name. To use TPM, use MS_PLATFORM_KEY_STORAGE_PROVIDER.
    // To use software provider, use MS_KEY_STORAGE_PROVIDER instead.
    constexpr LPCWSTR provider_name = MS_KEY_STORAGE_PROVIDER;

    // For some reason NCRYPT_REQUIRE_VBS_FLAG is not defined in the headers.
    constexpr DWORD require_vbs = 0x00020000;

    // To open the key for the local machine, set this to NCRYPT_MACHINE_KEY_FLAG.
    // Setting this to 0 opens the key for the current user.
    constexpr DWORD key_open_mode = 0;

    // Additional flags to specify only when creating a key.
    constexpr DWORD key_create_flags = require_vbs;

    ecdsa_p256 p256_crypto_params;
    ecdsa_p384 p384_crypto_params;
    ecdsa_p521 p521_crypto_params;

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

    const crypto_params& GetCryptoParams(mpss::SignatureAlgorithm algorithm)
    {
        switch (algorithm) {
        case mpss::SignatureAlgorithm::ECDSA_P256_SHA256:
            return p256_crypto_params;
        case mpss::SignatureAlgorithm::ECDSA_P384_SHA384:
            return p384_crypto_params;
        case mpss::SignatureAlgorithm::ECDSA_P521_SHA512:
            return p521_crypto_params;
        default:
            throw std::invalid_argument("Unsupported algorithm");
        }
    }

    class WindowsKeyPairHandle : public mpss::KeyPairHandle
    {
    public:
        WindowsKeyPairHandle(std::string_view name, mpss::SignatureAlgorithm algorithm, NCRYPT_KEY_HANDLE handle)
            : mpss::KeyPairHandle(name, algorithm), key_handle_(handle) {}

        virtual ~WindowsKeyPairHandle() = default;

        NCRYPT_KEY_HANDLE key_handle() const { return key_handle_; }

    private:
        NCRYPT_KEY_HANDLE key_handle_ = 0;
    };
}

namespace mpss
{
    namespace impl
    {
        std::optional<KeyPairHandle> create_key(std::string_view name, SignatureAlgorithm algorithm)
        {
            const crypto_params& crypto = GetCryptoParams(algorithm);

            NCRYPT_PROV_HANDLE provider_handle = GetProvider();
            if (!provider_handle) {
                return std::nullopt;
            }
            SCOPE_GUARD(::NCryptFreeObject(provider_handle));

            NCRYPT_KEY_HANDLE key_handle = 0;
            std::wstring wname(name.begin(), name.end());

            SECURITY_STATUS status = ::NCryptCreatePersistedKey(
                provider_handle,
                &key_handle,
                crypto.get_key_type_name(),
                wname.c_str(),
                key_spec,
                key_open_mode | key_create_flags);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptCreatePersistedKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return std::nullopt;
            }

            status = ::NCryptFinalizeKey(key_handle, /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptFinalizeKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return std::nullopt;
            }

            return std::make_optional<WindowsKeyPairHandle>(name, algorithm, key_handle);
        }

        std::optional<KeyPairHandle> open_key(std::string_view name)
        {
            SignatureAlgorithm algorithm = SignatureAlgorithm::Undefined;

            NCRYPT_KEY_HANDLE key_handle = GetKey(name);
            if (!key_handle) {
                return std::nullopt;
            }

            SCOPE_GUARD({
                if (algorithm != SignatureAlgorithm::Undefined) {
                    ::NCryptFreeObject(key_handle);
                }
            });

            // Get the algorithm name to deduce SignatureAlgorithm
            DWORD dwOutputSize = 0;
            SECURITY_STATUS status = ::NCryptGetProperty(
                key_handle,
                NCRYPT_ALGORITHM_PROPERTY,
                /* pbOutput */ nullptr,
                /* cbOutput */ 0,
                &dwOutputSize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptGetProperty failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return std::nullopt;
            }

            std::wstring algorithm_name(dwOutputSize, '\0');
            status = ::NCryptGetProperty(
                key_handle,
                NCRYPT_ALGORITHM_PROPERTY,
                reinterpret_cast<PBYTE>(&algorithm_name[0]),
                static_cast<DWORD>(algorithm_name.size()),
                &dwOutputSize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptGetProperty failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return std::nullopt;
            }

            if (algorithm_name == NCRYPT_ECDSA_P256_ALGORITHM) {
                algorithm = SignatureAlgorithm::ECDSA_P256_SHA256;
            }
            else if (algorithm_name == NCRYPT_ECDSA_P384_ALGORITHM) {
                algorithm = SignatureAlgorithm::ECDSA_P384_SHA384;
            }
            else if (algorithm_name == NCRYPT_ECDSA_P521_ALGORITHM) {
                algorithm = SignatureAlgorithm::ECDSA_P521_SHA512;
            }
            else {
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                std::string alg_name = converter.to_bytes(algorithm_name);
                std::stringstream ss;
                ss << "Unsupported algorithm: " << alg_name;
                set_error(ERROR_INVALID_PARAMETER, ss.str());
                return std::nullopt;
            }

            return std::make_optional<WindowsKeyPairHandle>(name, algorithm, key_handle);
        }

        int delete_key(const KeyPairHandle& handle)
        {
            const WindowsKeyPairHandle& win_handle = static_cast<const WindowsKeyPairHandle&>(handle);

            SECURITY_STATUS status = ::NCryptDeleteKey(win_handle.key_handle(), /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptDeleteKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            // Release the key handle.
            ::NCryptFreeObject(win_handle.key_handle());

            return 0;
        }

        std::string sign(const KeyPairHandle& handle, std::string_view hash)
        {
            const WindowsKeyPairHandle& win_handle = static_cast<const WindowsKeyPairHandle&>(handle);
            std::string signature;
            const crypto_params& crypto = GetCryptoParams(win_handle.algorithm());

            if (!utils::verify_hash_length(hash, win_handle.algorithm())) {
                std::stringstream ss;
                ss << "Invalid hash length for algorithm. Length is: " << hash.size();
                set_error(ERROR_INVALID_PARAMETER, ss.str());
                return signature;
            }

            DWORD signature_size = 0;

            // Get signature size.
            SECURITY_STATUS status = ::NCryptSignHash(
                win_handle.key_handle(),
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<PBYTE>(const_cast<char*>(hash.data())),
                hash.size(),
                /* pbSignature */ nullptr,
                /* cbSignature */ 0,
                &signature_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSignHash to get signature size failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return signature;
            }

            // Get the actual signature.
            signature.resize(signature_size);
            status = ::NCryptSignHash(
                win_handle.key_handle(),
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<PBYTE>(const_cast<char*>(hash.data())),
                hash.size(),
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

        int verify(const KeyPairHandle& handle, std::string_view hash, std::string_view signature)
        {
            const WindowsKeyPairHandle& win_handle = static_cast<const WindowsKeyPairHandle&>(handle);
            if (!utils::verify_hash_length(hash, win_handle.algorithm())) {
                std::stringstream ss;
                ss << "Invalid hash length for algorithm. Length is: " << hash.size();
                set_error(ERROR_INVALID_PARAMETER, ss.str());
                return -1;
            }

            SECURITY_STATUS status = ::NCryptVerifySignature(
                win_handle.key_handle(),
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<PBYTE>(const_cast<char*>(hash.data())),
                hash.size(),
                reinterpret_cast<PBYTE>(const_cast<char*>(signature.data())),
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

        int get_key(const KeyPairHandle& handle, std::string& vk_out)
        {
            const WindowsKeyPairHandle& win_handle = static_cast<const WindowsKeyPairHandle&>(handle);
            const crypto_params& crypto = GetCryptoParams(win_handle.algorithm());

            // Get the public key size.
            DWORD public_key_size = 0;
            SECURITY_STATUS status = ::NCryptExportKey(
                win_handle.key_handle(),
                /* hExportKey */ 0,
                crypto.get_public_key_blob_name(),
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
                win_handle.key_handle(),
                /* hExportKey */ 0,
                crypto.get_public_key_blob_name(),
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

            crypto_params::key_blob_t* public_key_blob_ptr = reinterpret_cast<crypto_params::key_blob_t*>(public_key_ptr);
            if (public_key_blob_ptr->dwMagic != crypto.get_public_key_magic()) {
                set_error(status, "Invalid public key magic");
                return -1;
            }

            BYTE* data_start_ptr = reinterpret_cast<BYTE*>(public_key_blob_ptr) + sizeof(crypto_params::key_blob_t);
            vk_out.assign(reinterpret_cast<char*>(data_start_ptr), public_key_size - sizeof(crypto_params::key_blob_t));

            return 0;
        }

        bool is_safe_storage_supported(SignatureAlgorithm algorithm)
        {
            // Check if the algorithm is supported.
            return false;
        }

        void release_key(const KeyPairHandle& handle)
        {
            const WindowsKeyPairHandle& win_handle = static_cast<const WindowsKeyPairHandle&>(handle);
            ::NCryptFreeObject(win_handle.key_handle());
        }

        std::string get_error()
        {
            return mpss::utils::get_error();
        }
    }
}
