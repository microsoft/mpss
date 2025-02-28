// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/implementations/windows/win_keypair.h"
#include "mpss/implementations/windows/win_utils.h"

#include <sstream>
#include <utility>
#include <string>
#include <locale>
#include <codecvt>
#include <cwchar>

#include <Windows.h>
#include <ncrypt.h>

#include <gsl/span>
#include <gsl/narrow>

namespace {
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

    NCRYPT_PROV_HANDLE GetProvider()
    {
        NCRYPT_PROV_HANDLE provider_handle = 0;

        // This function uses no extra flags.
        DWORD flags = 0;

        SECURITY_STATUS status = ::NCryptOpenStorageProvider(&provider_handle, provider_name, flags);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenStorageProvider failed with error code " << mpss::utils::to_hex(status);
            mpss::impl::utils::set_error(status, ss.str());
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
            mpss::impl::utils::set_error(status, ss.str());
            return 0;
        }

        return key_handle;
    }
}

namespace mpss::impl
{
    std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
    {
        const crypto_params &crypto = utils::get_crypto_params(algorithm);

        NCRYPT_PROV_HANDLE provider_handle = GetProvider();
        if (!provider_handle) {
            return nullptr;
        }
        SCOPE_GUARD(::NCryptFreeObject(provider_handle));

        NCRYPT_KEY_HANDLE key_handle = 0;
        std::wstring wname(name.begin(), name.end());

        SECURITY_STATUS status = ::NCryptCreatePersistedKey(
            provider_handle,
            &key_handle,
            crypto.key_type_name(),
            wname.c_str(),
            key_spec,
            key_open_mode | key_create_flags);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptCreatePersistedKey failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return nullptr;
        }

        status = ::NCryptFinalizeKey(key_handle, /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptFinalizeKey failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return nullptr;
        }

        return std::make_unique<WindowsKeyPair>(name, algorithm, key_handle);
    }

    std::unique_ptr<KeyPair> open_key(std::string_view name)
    {
        Algorithm algorithm;

        NCRYPT_KEY_HANDLE key_handle = GetKey(name);
        if (!key_handle) {
            return nullptr;
        }

        SCOPE_GUARD({
            // Release if algorithm is not set, which means there was an error opening the key
            if (algorithm == Algorithm::unsupported) {
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
            utils::set_error(status, ss.str());
            return nullptr;
        }

        std::wstring algorithm_name(dwOutputSize, '\0');
        status = ::NCryptGetProperty(
            key_handle,
            NCRYPT_ALGORITHM_PROPERTY,
            reinterpret_cast<PBYTE>(&algorithm_name[0]),
            gsl::narrow<DWORD>(algorithm_name.size()),
            &dwOutputSize,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptGetProperty failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return nullptr;
        }

        if (algorithm_name.compare(/* offset */ 0, std::wcslen(NCRYPT_ECDSA_P256_ALGORITHM), NCRYPT_ECDSA_P256_ALGORITHM) == 0) {
            algorithm = Algorithm::ecdsa_secp256r1_sha256;
        }
        else if (algorithm_name.compare(/* offset */ 0, std::wcslen(NCRYPT_ECDSA_P384_ALGORITHM), NCRYPT_ECDSA_P384_ALGORITHM) == 0) {
            algorithm = Algorithm::ecdsa_secp384r1_sha384;
        }
        else if (algorithm_name.compare(/* offset */ 0, std::wcslen(NCRYPT_ECDSA_P521_ALGORITHM), NCRYPT_ECDSA_P521_ALGORITHM) == 0) {
            algorithm = Algorithm::ecdsa_secp521r1_sha512;
        }
        else {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::string alg_name = converter.to_bytes(algorithm_name);
            std::stringstream ss;
            ss << "Unsupported algorithm: " << alg_name;
            utils::set_error(ERROR_INVALID_PARAMETER, ss.str());
            return nullptr;
        }

        return std::make_unique<WindowsKeyPair>(name, algorithm, key_handle);
    }

    std::string get_error()
    {
        return mpss::utils::get_error();
    }
}
