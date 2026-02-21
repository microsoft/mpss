// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/implementations/apple/apple_api_wrapper.h"
#include "mpss/implementations/apple/apple_keychain_keypair.h"
#include "mpss/implementations/apple/apple_se_keypair.h"
#include "mpss/implementations/apple/apple_se_wrapper.h"
#include "mpss/implementations/apple/apple_utils.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

using enum Algorithm;

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }

    // Try secure enclave first if available.
    mpss::utils::log_debug("Attempting to open key '{}' on Apple backend.", key_name);
    if (MPSS_SE_SecureEnclaveIsSupported() && MPSS_SE_OpenExistingKey(key_name.c_str()))
    {
        // If the key was found, it *has* to be an ECDSA P256 key, since that's the only type of key supported by
        // the Secure Enclave.
        mpss::utils::log_debug("Key '{}' found in Secure Enclave.", key_name);
        return std::make_unique<AppleSEKeyPair>(key_name, ecdsa_secp256r1_sha256);
    }

    int bitSize = 0;
    if (MPSS_OpenExistingKey(key_name.c_str(), &bitSize))
    {
        Algorithm algorithm = unsupported;
        switch (bitSize)
        {
        case 256:
            algorithm = ecdsa_secp256r1_sha256;
            break;
        case 384:
            algorithm = ecdsa_secp384r1_sha384;
            break;
        case 521:
            algorithm = ecdsa_secp521r1_sha512;
            break;
        default:
            mpss::utils::log_warn("Opened a key, but it has unsupported bit size: {}", bitSize);
            MPSS_RemoveKey(key_name.c_str());
            return nullptr;
        }

        mpss::utils::log_debug("Key '{}' found in Keychain with algorithm '{}'.", key_name,
                               get_algorithm_info(algorithm).type_str);
        return std::make_unique<AppleKeychainKeyPair>(key_name, algorithm);
    }

    mpss::utils::log_info("Key not found: {}", key_name);
    return nullptr;
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
{
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warn("Unsupported algorithm: {}", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    // Fail if the key already exists or is already open.
    std::unique_ptr<KeyPair> existing_key = open_key(name);
    if (nullptr != existing_key)
    {
        mpss::utils::log_warn("Key already exists: {}", name);
        return nullptr;
    }

    if (MPSS_SE_SecureEnclaveIsSupported() && ecdsa_secp256r1_sha256 == algorithm)
    {
        // Secure Enclave only supports ECDSA P256.
        mpss::utils::log_debug("Creating key '{}' in Secure Enclave.", key_name);
        if (MPSS_SE_CreateKey(key_name.c_str()))
        {
            mpss::utils::log_debug("Key '{}' created successfully in Secure Enclave.", key_name);
            return std::make_unique<AppleSEKeyPair>(name, algorithm);
        }

        mpss::utils::log_and_set_error("Failed to create key in Secure Enclave: {}", utils::MPSS_SE_GetLastError());
        return nullptr;
    }

    mpss::utils::log_debug("Creating key '{}' in Keychain.", key_name);
    if (MPSS_CreateKey(key_name.c_str(), static_cast<int>(algorithm)))
    {
        mpss::utils::log_debug("Key '{}' created successfully in Keychain.", key_name);
        return std::make_unique<AppleKeychainKeyPair>(name, algorithm);
    }

    mpss::utils::log_and_set_error("Failed to create key in keychain: {}", MPSS_GetLastError());
    return nullptr;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_warn("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warn("Unsupported algorithm: {}", get_algorithm_info(algorithm).type_str);
        return false;
    }

    // Check hash length.
    if (!mpss::utils::check_exact_hash_size(hash, algorithm))
    {
        return false;
    }

    if (MPSS_SE_SecureEnclaveIsSupported() && ecdsa_secp256r1_sha256 == algorithm)
    {
        // Secure Enclave only supports ECDSA P256.
        const bool result = MPSS_SE_VerifyStandaloneSignature(
            reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
            reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
            reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());

        mpss::utils::log_info("Verification using (Secure Enclave) standalone signature verification {}.",
                              result ? "succeeded" : "failed");
        return result;
    }

    const bool result = MPSS_VerifyStandaloneSignature(
        static_cast<int>(algorithm), reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
        reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
        reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());

    mpss::utils::log_info("Verification using (Keychain) standalone signature verification {}.",
                          result ? "succeeded" : "failed");
    return result;
}

} // namespace mpss::impl::os
