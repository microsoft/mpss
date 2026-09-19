// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/apple/apple_keychain_keypair.h"
#include "mpss/impl/apple/apple_api_wrapper.h"
#include "mpss/impl/apple/apple_utils.h"
#include "mpss/utils/utilities.h"

namespace
{
constexpr const char *storage_description = "Keychain";
}

namespace mpss::impl::os
{

AppleKeychainKeyPair::AppleKeychainKeyPair(std::string_view name, Algorithm algorithm, std::uint64_t generation)
    : AppleKeyPairBase{name, algorithm, /* hardware_backed */ false, storage_description, generation}
{
}

AppleKeychainKeyPair::~AppleKeychainKeyPair()
{
    release_key();
}

bool AppleKeychainKeyPair::do_delete_key()
{
    mpss::utils::log_trace("Deleting Keychain key '{}'.", name());

    // Deleting reaches the name rather than the entry this handle opened, so refuse once the name
    // has moved on. Otherwise a handle to a deleted key would delete the key that replaced it.
    if (!MPSS_KeychainGenerationIsCurrent(name().c_str(), generation()))
    {
        mpss::utils::log_and_set_error("Key '{}' is no longer the key this handle opened.", name());
        return false;
    }

    const bool result = utils::delete_key_from_all_tiers(name());
    if (result)
    {
        mpss::utils::log_trace("Keychain key '{}' deleted.", name());
    }

    return result;
}

std::size_t AppleKeychainKeyPair::do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    mpss::utils::log_trace("Signing hash with Keychain key '{}', hash size {}.", name(), hash.size());
    std::size_t signature_size = sig.size();

    if (!MPSS_SignHash(name().c_str(), static_cast<int>(algorithm()), generation(),
                       reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
                       reinterpret_cast<std::uint8_t *>(sig.data()), &signature_size))
    {
        // This should not fail at this point. The caller already validated inputs.
        utils::report_keychain_error("sign hash");
        return 0;
    }

    mpss::utils::log_trace("Keychain sign produced {} byte signature.", signature_size);
    return signature_size;
}

bool AppleKeychainKeyPair::do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    const std::int32_t raw_result =
        MPSS_VerifySignature(name().c_str(), static_cast<int>(algorithm()), generation(),
                             reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
                             reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());
    return utils::handle_keychain_verification_result(raw_result, "verify signature");
}

std::size_t AppleKeychainKeyPair::do_extract_key(std::span<std::byte> public_key) const
{
    mpss::utils::log_trace("Extracting public key from Keychain key '{}'.", name());
    std::size_t pk_size = public_key.size();

    if (!MPSS_GetPublicKey(name().c_str(), generation(), reinterpret_cast<std::uint8_t *>(public_key.data()), &pk_size))
    {
        // This should not fail at this point. The caller already validated inputs.
        utils::report_keychain_error("retrieve public key");
        return 0;
    }

    mpss::utils::log_trace("Extracted {} byte public key from Keychain key '{}'.", pk_size, name());
    return pk_size;
}

bool AppleKeychainKeyPair::do_release_key()
{
    // Gives up a hold on an in-memory cache entry, which cannot fail.
    MPSS_RemoveKey(name().c_str(), generation());
    return true;
}

} // namespace mpss::impl::os
