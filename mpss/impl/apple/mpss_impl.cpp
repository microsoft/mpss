// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/impl/apple/apple_api_wrapper.h"
#include "mpss/impl/apple/apple_keychain_keypair.h"
#include "mpss/impl/apple/apple_se_keypair.h"
#include "mpss/impl/apple/apple_se_wrapper.h"
#include "mpss/impl/apple/apple_utils.h"
#include "mpss/impl/key_probe.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

using enum Algorithm;

namespace
{

using OpenKeyResult = KeyProbeResult<std::unique_ptr<KeyPair>>;

// The two tiers store their keys as different Keychain item classes, so one name can be held in
// both at once. Resolving to whichever tier answers first would let a key planted in the tier the
// name was not created in decide what the name means, so a name held twice is refused instead.
bool keychain_tier_also_holds(const std::string &key_name, bool &indeterminate)
{
    using enum utils::AppleOperationResult;

    indeterminate = false;
    const std::int32_t raw_result = MPSS_KeychainKeyExists(key_name.c_str());
    switch (utils::decode_apple_result(raw_result))
    {
    case success:
        return true;
    case expected_negative:
        return false;
    case operational_error:
        utils::report_keychain_error("determine whether the Keychain holds the name");
        indeterminate = true;
        return false;
    case invalid_result:
        utils::report_invalid_apple_result("Keychain", "determine whether the Keychain holds the name", raw_result);
        indeterminate = true;
        return false;
    }

    indeterminate = true;
    return false;
}

OpenKeyResult try_open_key(const std::string &key_name)
{
    using enum utils::AppleOperationResult;

    mpss::utils::log_trace("Attempting to open key '{}' on Apple backend.", key_name);
    if (MPSS_SE_SecureEnclaveIsSupported())
    {
        const std::int32_t raw_result = MPSS_SE_OpenExistingKey(key_name.c_str());
        switch (utils::decode_apple_result(raw_result))
        {
        case success: {
            bool indeterminate = false;
            const bool also_in_keychain = keychain_tier_also_holds(key_name, indeterminate);
            if (indeterminate)
            {
                // The open failed, so no key pair will be constructed to evict the cache entry that
                // the lookup above populated.
                MPSS_SE_CloseKey(key_name.c_str());
                return {.status = KeyProbeStatus::operational_error, .value = nullptr};
            }
            if (also_in_keychain)
            {
                MPSS_SE_CloseKey(key_name.c_str());
                mpss::utils::log_and_set_error(
                    "Refusing to open key '{}': the name is held in both the Secure Enclave and the Keychain.",
                    key_name);
                return {.status = KeyProbeStatus::operational_error, .value = nullptr};
            }

            mpss::utils::log_trace("Key '{}' found in Secure Enclave.", key_name);
            return {.status = KeyProbeStatus::found,
                    .value = std::make_unique<AppleSEKeyPair>(key_name, ecdsa_secp256r1_sha256)};
        }
        case expected_negative:
            break;
        case operational_error:
            utils::report_secure_enclave_error("open key");
            return {.status = KeyProbeStatus::operational_error, .value = nullptr};
        case invalid_result:
            utils::report_invalid_apple_result("Secure Enclave", "open key", raw_result);
            return {.status = KeyProbeStatus::operational_error, .value = nullptr};
        }
    }

    int bit_size = 0;
    const std::int32_t raw_result = MPSS_OpenExistingKey(key_name.c_str(), &bit_size);
    switch (utils::decode_apple_result(raw_result))
    {
    case success:
        break;
    case expected_negative:
        return {.status = KeyProbeStatus::not_found, .value = nullptr};
    case operational_error:
        utils::report_keychain_error("open key");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    case invalid_result:
        utils::report_invalid_apple_result("Keychain", "open key", raw_result);
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    Algorithm algorithm = unsupported;
    switch (bit_size)
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
        MPSS_RemoveKey(key_name.c_str());
        mpss::utils::log_and_set_error("Opened key '{}' has unsupported bit size {}.", key_name, bit_size);
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    mpss::utils::log_trace("Key '{}' found in Keychain with algorithm '{}'.", key_name,
                           get_algorithm_info(algorithm).type_str);
    return {.status = KeyProbeStatus::found, .value = std::make_unique<AppleKeychainKeyPair>(key_name, algorithm)};
}

} // namespace

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    mpss::utils::clear_error();
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    OpenKeyResult result = try_open_key(key_name);
    if (KeyProbeStatus::not_found == result.status)
    {
        mpss::utils::log_debug("Key '{}' not found.", key_name);
    }

    return std::move(result.value);
}

bool delete_key(std::string_view name)
{
    mpss::utils::clear_error();
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return false;
    }

    return utils::delete_key_from_all_tiers(key_name);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy)
{
    mpss::utils::clear_error();
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    constexpr auto supported_policy = static_cast<std::uint64_t>(KeyPolicy::apple_secure_enclave_user_presence);
    const auto raw_policy = static_cast<std::uint64_t>(policy);
    if (0 != (raw_policy & ~supported_policy))
    {
        mpss::utils::log_and_set_error("Apple backend does not support the requested key policy.");
        return nullptr;
    }

    const bool require_user_presence = KeyPolicy::none != (policy & KeyPolicy::apple_secure_enclave_user_presence);
    const bool secure_enclave_supported = MPSS_SE_SecureEnclaveIsSupported();
    if (require_user_presence && (!secure_enclave_supported || ecdsa_secp256r1_sha256 != algorithm))
    {
        mpss::utils::log_and_set_error(
            "Apple Secure Enclave user presence requires ecdsa_secp256r1_sha256 and an available Secure Enclave.");
        return nullptr;
    }

    OpenKeyResult existing_key = try_open_key(key_name);
    if (KeyProbeStatus::operational_error == existing_key.status)
    {
        return nullptr;
    }
    if (KeyProbeStatus::found == existing_key.status)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    if (secure_enclave_supported && ecdsa_secp256r1_sha256 == algorithm)
    {
        // Secure Enclave only supports ECDSA P256.
        mpss::utils::log_trace("Creating key '{}' in Secure Enclave.", key_name);
        if (MPSS_SE_CreateKey(key_name.c_str(), require_user_presence))
        {
            mpss::utils::log_trace("Key '{}' created in Secure Enclave.", key_name);
            return std::make_unique<AppleSEKeyPair>(name, algorithm);
        }

        utils::report_secure_enclave_error("create key");
        return nullptr;
    }

    mpss::utils::log_trace("Creating key '{}' in Keychain.", key_name);
    if (MPSS_CreateKey(key_name.c_str(), static_cast<int>(algorithm)))
    {
        mpss::utils::log_trace("Key '{}' created in Keychain.", key_name);
        return std::make_unique<AppleKeychainKeyPair>(name, algorithm);
    }

    utils::report_keychain_error("create key");
    return nullptr;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    mpss::utils::clear_error();
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_and_set_error("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
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
        const std::int32_t raw_result = MPSS_SE_VerifyStandaloneSignature(
            reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
            reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
            reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());
        const bool result = utils::handle_secure_enclave_verification_result(raw_result, "verify signature");
        mpss::utils::log_trace("Verification using (Secure Enclave) standalone signature verification {}.",
                               result ? "succeeded" : "failed");
        return result;
    }

    const std::int32_t raw_result = MPSS_VerifyStandaloneSignature(
        static_cast<int>(algorithm), reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
        reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
        reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());
    const bool result = utils::handle_keychain_verification_result(raw_result, "verify signature");
    mpss::utils::log_trace("Verification using (Keychain) standalone signature verification {}.",
                           result ? "succeeded" : "failed");
    return result;
}

} // namespace mpss::impl::os
