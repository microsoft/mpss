// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/apple/apple_keychain_keypair.h"
#include "mpss/implementations/apple/apple_api_wrapper.h"
#include "mpss/utils/utilities.h"

namespace
{
constexpr const char *storage_description = "Keychain";
}

namespace mpss::impl::os
{

AppleKeychainKeyPair::AppleKeychainKeyPair(std::string_view name, Algorithm algorithm)
    : AppleKeyPairBase{name, algorithm, /* hardware_backed */ false, storage_description}
{
}

AppleKeychainKeyPair::~AppleKeychainKeyPair()
{
    release_key();
}

bool AppleKeychainKeyPair::do_delete_key()
{
    mpss::utils::log_debug("Deleting Keychain key '{}'.", name());
    const bool result = MPSS_DeleteKey(name().c_str());
    if (!result)
    {
        mpss::utils::log_and_set_error("Failed to delete key: {}", MPSS_GetLastError());
    }
    else
    {
        mpss::utils::log_debug("Keychain key '{}' deleted.", name());
    }

    return result;
}

std::size_t AppleKeychainKeyPair::do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    mpss::utils::log_debug("Signing hash with Keychain key '{}', hash size {}.", name(), hash.size());
    std::size_t signature_size = sig.size();

    if (!MPSS_SignHash(name().c_str(), static_cast<int>(algorithm()),
                       reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
                       reinterpret_cast<std::uint8_t *>(sig.data()), &signature_size))
    {
        // This should not fail at this point. The caller already validated inputs.
        mpss::utils::log_and_set_error("Failed to sign hash: {}", MPSS_GetLastError());
        return 0;
    }

    mpss::utils::log_debug("Keychain sign produced {} byte signature.", signature_size);
    return signature_size;
}

bool AppleKeychainKeyPair::do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    const bool result = MPSS_VerifySignature(name().c_str(), static_cast<int>(algorithm()),
                                             reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
                                             reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());

    // This should not fail at this point unless the signature is invalid. The caller already validated inputs.
    return result;
}

std::size_t AppleKeychainKeyPair::do_extract_key(std::span<std::byte> public_key) const
{
    mpss::utils::log_debug("Extracting public key from Keychain key '{}'.", name());
    std::size_t pk_size = public_key.size();

    if (!MPSS_GetPublicKey(name().c_str(), reinterpret_cast<std::uint8_t *>(public_key.data()), &pk_size))
    {
        // This should not fail at this point. The caller already validated inputs.
        mpss::utils::log_and_set_error("Failed to retrieve public key: {}", MPSS_GetLastError());
        return 0;
    }

    mpss::utils::log_debug("Extracted {} byte public key from Keychain key '{}'.", pk_size, name());
    return pk_size;
}

void AppleKeychainKeyPair::do_release_key()
{
    MPSS_RemoveKey(name().c_str());
}

} // namespace mpss::impl::os
