// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/implementations/windows/win_keypair.h"
#include "mpss/implementations/windows/win_utils.h"
#include <Windows.h>
#include <codecvt>
#include <cwchar>
#include <gsl/narrow>
#include <gsl/span>
#include <locale>
#include <ncrypt.h>
#include <sstream>
#include <string>
#include <utility>

namespace {
    // Legacy key spec. We only store signing keys.
    constexpr DWORD key_spec = 0;

    // Choose the provider name. To use TPM, use MS_PLATFORM_KEY_STORAGE_PROVIDER.
    // To use software provider, use MS_KEY_STORAGE_PROVIDER instead.
    constexpr LPCWSTR provider_name = MS_KEY_STORAGE_PROVIDER;

    // The fallback provider will be used if we cannot create a key backed by VBS.
    constexpr LPCWSTR fallback_provider_name = MS_PLATFORM_KEY_STORAGE_PROVIDER;

    // A description of our default provider
    constexpr LPCSTR provider_description = "Virtualization Based Security";

    // A description of our fallback provider
    constexpr LPCSTR fallback_provider_description = "TPM Protection";

    // For some reason NCRYPT_REQUIRE_VBS_FLAG is not defined in the headers.
    constexpr DWORD require_vbs = 0x00020000;

    // To open the key for the local machine, set this to NCRYPT_MACHINE_KEY_FLAG.
    // Setting this to 0 opens the key for the current user.
    constexpr DWORD key_open_mode = 0;

    // Additional flags to specify only when creating a key.
    constexpr DWORD key_create_flags = require_vbs;

    // Additional flags to specify only when creating a fallback key.
    constexpr DWORD key_create_flags_fallback = 0;

    NCRYPT_PROV_HANDLE GetProvider(bool fallback = false)
    {
        NCRYPT_PROV_HANDLE provider_handle = 0;

        // This function uses no extra flags.
        DWORD flags = 0;

        LPCWSTR provider_name_to_use = fallback ? fallback_provider_name : provider_name;

        SECURITY_STATUS status =
            ::NCryptOpenStorageProvider(&provider_handle, provider_name_to_use, flags);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenStorageProvider failed with error code "
               << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return 0;
        }

        if (provider_handle == 0) {
            mpss::utils::set_error("Provider handle is null.");
            return 0;
        }

        return provider_handle;
    }

    NCRYPT_KEY_HANDLE GetKeyFromProvider(std::string_view name, bool fallback)
    {
        NCRYPT_PROV_HANDLE provider_handle = GetProvider(fallback);
        if (!provider_handle) {
            return 0;
        }

        SCOPE_GUARD(::NCryptFreeObject(provider_handle));
        NCRYPT_KEY_HANDLE key_handle = 0;
        std::wstring wname(name.begin(), name.end());

        SECURITY_STATUS status =
            ::NCryptOpenKey(provider_handle, &key_handle, wname.c_str(), key_spec, key_open_mode);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenKey failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return 0;
        }

        return key_handle;
    }

    NCRYPT_KEY_HANDLE GetKey(std::string_view name, const char **storage_description)
    {
        *storage_description = nullptr;

        // Try to open the key using the primary provider.
        NCRYPT_KEY_HANDLE key_handle = GetKeyFromProvider(name, /* fallback */ false);
        if (key_handle) {
            *storage_description = provider_description;
            return key_handle;
        }
        std::string error = mpss::utils::get_error();

        // Try to open the key using the fallback provider.
        key_handle = GetKeyFromProvider(name, /* fallback */ true);
        if (key_handle) {
            *storage_description = fallback_provider_description;
            return key_handle;
        }

        // If we get here, we failed to open the key in both providers.
        // Report both errors.
        std::stringstream ss;
        ss << error;
        ss << ", fallback: " << mpss::utils::get_error();
        mpss::utils::set_error(ss.str());

        return 0;
    }

    NCRYPT_KEY_HANDLE CreateKey(std::string_view name, mpss::Algorithm algorithm, bool fallback)
    {
        mpss::impl::crypto_params const *const crypto =
            mpss::impl::utils::get_crypto_params(algorithm);
        if (!crypto) {
            mpss::utils::set_error("Unsupported algorithm.");
            return 0;
        }

        NCRYPT_PROV_HANDLE provider_handle = GetProvider(fallback);
        if (!provider_handle) {
            return 0;
        }
        SCOPE_GUARD(::NCryptFreeObject(provider_handle));

        NCRYPT_KEY_HANDLE key_handle = 0;
        std::wstring wname(name.begin(), name.end());

        DWORD creation_flags = fallback ? key_create_flags_fallback : key_create_flags;

        SECURITY_STATUS status = ::NCryptCreatePersistedKey(
            provider_handle,
            &key_handle,
            crypto->key_type_name(),
            wname.c_str(),
            key_spec,
            key_open_mode | creation_flags);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptCreatePersistedKey failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return 0;
        }

        status = ::NCryptFinalizeKey(key_handle, /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptFinalizeKey failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return 0;
        }

        return key_handle;
    }

    mpss::Algorithm GetAlgorithmFromName(NCRYPT_KEY_HANDLE key_handle)
    {
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
            ss << "NCryptGetProperty (algorithm) failed with error code "
               << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return mpss::Algorithm::unsupported;
        }

        std::wstring algorithm_name(dwOutputSize, '\0');
        DWORD algorithm_name_size = mpss::utils::narrow_or_error<DWORD>(algorithm_name.size());
        if (!algorithm_name_size) {
            return mpss::Algorithm::unsupported;
        }

        status = ::NCryptGetProperty(
            key_handle,
            NCRYPT_ALGORITHM_PROPERTY,
            reinterpret_cast<PBYTE>(&algorithm_name[0]),
            algorithm_name_size,
            &dwOutputSize,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptGetProperty failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return mpss::Algorithm::unsupported;
        }

        if (algorithm_name.compare(/* offset */ 0,
                                   std::wcslen(NCRYPT_ECDSA_P256_ALGORITHM),
                                   NCRYPT_ECDSA_P256_ALGORITHM) == 0) {
            return mpss::Algorithm::ecdsa_secp256r1_sha256;
        } else if (
            algorithm_name.compare(/* offset */ 0,
                                   std::wcslen(NCRYPT_ECDSA_P384_ALGORITHM),
                                   NCRYPT_ECDSA_P384_ALGORITHM) == 0) {
            return mpss::Algorithm::ecdsa_secp384r1_sha384;
        } else if (
            algorithm_name.compare(/* offset */ 0,
                                   std::wcslen(NCRYPT_ECDSA_P521_ALGORITHM),
                                   NCRYPT_ECDSA_P521_ALGORITHM) == 0) {
            return mpss::Algorithm::ecdsa_secp521r1_sha512;
        } else {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::string alg_name = converter.to_bytes(algorithm_name);
            std::stringstream ss;
            ss << "Unsupported algorithm: " << alg_name;
            mpss::utils::set_error(ss.str());
            return mpss::Algorithm::unsupported;
        }
    }

    std::size_t GetKeyLength(NCRYPT_KEY_HANDLE key_handle)
    {
        DWORD dwKeyLength = 0;
        DWORD dwOutputSize = 0;

        SECURITY_STATUS status = ::NCryptGetProperty(
            key_handle,
            NCRYPT_LENGTH_PROPERTY,
            reinterpret_cast<PBYTE>(&dwKeyLength),
            sizeof(DWORD),
            &dwOutputSize,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptGetProperty (length) failed with error code "
               << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return 0;
        }

        return static_cast<std::size_t>(dwKeyLength);
    }

    mpss::Algorithm GetAlgorithmFromKeyBits(std::size_t key_bits)
    {
        switch (key_bits) {
        case 256:
            return mpss::Algorithm::ecdsa_secp256r1_sha256;
        case 384:
            return mpss::Algorithm::ecdsa_secp384r1_sha384;
        case 521:
            return mpss::Algorithm::ecdsa_secp521r1_sha512;
        default:
            return mpss::Algorithm::unsupported;
        }
    }
} // namespace

namespace mpss::impl {
    std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
    {
        // Fail if the key already exists.
        std::unique_ptr<KeyPair> existing = open_key(name);
        if (existing) {
            std::stringstream ss;
            ss << "Key already exists: " << name;
            mpss::utils::set_error(ss.str());
            return {};
        }

        // Try to create the key using the primary provider.
        NCRYPT_KEY_HANDLE key_handle = CreateKey(name, algorithm, /* fallback */ false);
        if (key_handle) {
            return std::make_unique<WindowsKeyPair>(
                algorithm, key_handle, /* hardware_backed */ true, provider_description);
        }

        std::string error = mpss::utils::get_error();

        // Try to create the key using the fallback provider.
        key_handle = CreateKey(name, algorithm, /* fallback */ true);
        if (key_handle) {
            return std::make_unique<WindowsKeyPair>(
                algorithm, key_handle, /* hardware_backed */ true, fallback_provider_description);
        }

        // If we get here, we failed to create the key in both providers.
        // Report both errors.
        std::stringstream ss;
        ss << error;
        ss << ", fallback: " << mpss::utils::get_error();
        mpss::utils::set_error(ss.str());

        return {};
    }

    std::unique_ptr<KeyPair> open_key(std::string_view name)
    {
        Algorithm algorithm;

        const char *storage_description = nullptr;
        NCRYPT_KEY_HANDLE key_handle = GetKey(name, &storage_description);
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
        algorithm = GetAlgorithmFromName(key_handle);
        if (algorithm == Algorithm::unsupported) {
            // Try directly with the key size
            algorithm = GetAlgorithmFromKeyBits(GetKeyLength(key_handle));
            if (algorithm == Algorithm::unsupported) {
                return nullptr;
            }
        }

        return std::make_unique<WindowsKeyPair>(
            algorithm, key_handle, /* hardware_backed */ true, storage_description);
    }

    bool verify(
        gsl::span<const std::byte> hash,
        gsl::span<const std::byte> public_key,
        Algorithm algorithm,
        gsl::span<const std::byte> sig)
    {
        // Check for obvious problems.
        if (hash.empty() || public_key.empty() || sig.empty()) {
            mpss::utils::set_error("Nothing to verify.");
            return false;
        }

        // Check hash length
        if (!mpss::utils::check_hash_length(hash, algorithm)) {
            mpss::utils::set_error("Invalid hash length for algorithm");
            return false;
        }

        // Check compression indicator
        if (public_key[0] != std::byte{ 0x04 }) {
            mpss::utils::set_error("Invalid public key format.");
            return false;
        }

        // Get the algorithm info.
        AlgorithmInfo info = get_algorithm_info(algorithm);

        // Get crypto parameters
        crypto_params const *const crypto = utils::get_crypto_params(algorithm);
        if (!crypto) {
            mpss::utils::set_error("Unsupported algorithm.");
            return false;
        }

        // Build the key blob
        DWORD pk_blob_size = sizeof(crypto_params::key_blob_t) + public_key.size() - 1;
        std::unique_ptr<BYTE[]> key_blob_buffer = std::make_unique<BYTE[]>(pk_blob_size);
        if (!key_blob_buffer) {
            mpss::utils::set_error("Failed to allocate key blob buffer.");
            return false;
        }
        SCOPE_GUARD({
            // Zero out the key blob buffer.
            ::SecureZeroMemory(key_blob_buffer.get(), pk_blob_size);
        });

        crypto_params::key_blob_t *key_blob =
            reinterpret_cast<crypto_params::key_blob_t *>(key_blob_buffer.get());
        key_blob->dwMagic = crypto->public_key_magic();
        // Field size, apparently
        key_blob->cbKey = mpss::utils::narrow_or_error<ULONG>((info.key_bits + 7) / 8);
        if (!key_blob->cbKey) {
            return false;
        }

        // Copy public key data to the blob
        std::transform(
            public_key.begin() + 1,
            public_key.end(),
            key_blob_buffer.get() + sizeof(crypto_params::key_blob_t),
            [](auto in) { return static_cast<BYTE>(in); });

        NCRYPT_PROV_HANDLE provider = GetProvider();
        if (!provider) {
            return false;
        }
        SCOPE_GUARD(::NCryptFreeObject(provider));

        // Import the public key
        NCRYPT_KEY_HANDLE key_handle = 0;
        SECURITY_STATUS status = ::NCryptImportKey(
            provider,
            /* hImportKey */ 0,
            crypto->public_key_blob_name(),
            /* pParameterList */ nullptr,
            &key_handle,
            key_blob_buffer.get(),
            pk_blob_size,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptImportKey failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return false;
        }
        if (!key_handle) {
            mpss::utils::set_error("Failed to import key.");
            return false;
        }
        SCOPE_GUARD(::NCryptFreeObject(key_handle));

        // Extract raw signature
        std::size_t raw_sig_size = mpss::impl::utils::decode_raw_signature(sig, algorithm, {});
        if (raw_sig_size == 0) {
            std::stringstream ss;
            ss << "Failed to get raw signature size: " << mpss::utils::get_error();
            mpss::utils::set_error(ss.str());
            return false;
        }

        std::vector<std::byte> raw_sig(raw_sig_size);
        SCOPE_GUARD({
            // Zero out the signature buffer.
            ::SecureZeroMemory(raw_sig.data(), raw_sig.size());
        });
        std::size_t written = mpss::impl::utils::decode_raw_signature(sig, algorithm, raw_sig);

        DWORD hash_size = mpss::utils::narrow_or_error<DWORD>(hash.size());
        if (!hash_size) {
            return false;
        }

        status = ::NCryptVerifySignature(
            key_handle,
            /* pPaddingInfo */ nullptr,
            reinterpret_cast<PBYTE>(const_cast<std::byte *>(hash.data())),
            hash_size,
            reinterpret_cast<PBYTE>(raw_sig.data()),
            raw_sig.size(),
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptVerifySignature failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return false;
        }

        return true;
    }
} // namespace mpss::impl
