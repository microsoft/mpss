// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/apple/apple_se_keypair.h"
#include "mpss/impl/apple/apple_se_wrapper.h"
#include "mpss/impl/apple/apple_utils.h"
#include "mpss/utils/utilities.h"

namespace
{
constexpr const char *storage_description = "Secure Enclave";
}

namespace mpss::impl::os
{

AppleSEKeyPair::AppleSEKeyPair(std::string_view name, Algorithm algorithm)
    : AppleKeyPairBase{name, algorithm, /* hardware_backed */ true, storage_description}
{
}

AppleSEKeyPair::~AppleSEKeyPair()
{
    release_key();
}

bool AppleSEKeyPair::do_delete_key()
{
    mpss::utils::log_trace("Deleting Secure Enclave key '{}'.", name());
    if (!MPSS_SE_RemoveExistingKey(name().c_str()))
    {
        mpss::utils::log_and_set_error("Failed to delete Secure Enclave key: {}", utils::MPSS_SE_GetLastError());
        return false;
    }
    mpss::utils::log_trace("Secure Enclave key '{}' deleted.", name());
    return true;
}

std::size_t AppleSEKeyPair::do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    mpss::utils::log_trace("Signing hash with Secure Enclave key '{}', hash size {}.", name(), hash.size());
    std::size_t signature_size = sig.size();

    if (!MPSS_SE_Sign(name().c_str(), reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
                      reinterpret_cast<std::uint8_t *>(sig.data()), &signature_size))
    {
        mpss::utils::log_and_set_error("Failed to sign hash: {}", utils::MPSS_SE_GetLastError());
        return 0;
    }

    mpss::utils::log_trace("Secure Enclave sign produced {} byte signature.", signature_size);
    return signature_size;
}

bool AppleSEKeyPair::do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    const bool result =
        MPSS_SE_VerifySignature(name().c_str(), reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
                                reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());

    // This should not fail at this point unless the signature is invalid. The caller already validated inputs.
    return result;
}

std::size_t AppleSEKeyPair::do_extract_key(std::span<std::byte> public_key) const
{
    mpss::utils::log_trace("Extracting public key from Secure Enclave key '{}'.", name());
    std::size_t pk_size = public_key.size();

    const bool result =
        MPSS_SE_GetPublicKey(name().c_str(), reinterpret_cast<std::uint8_t *>(public_key.data()), &pk_size);
    if (!result)
    {
        mpss::utils::log_and_set_error("Failed to retrieve public key: {}", utils::MPSS_SE_GetLastError());
        return 0;
    }

    mpss::utils::log_trace("Extracted {} byte public key from Secure Enclave key '{}'.", pk_size, name());
    return pk_size;
}

void AppleSEKeyPair::do_release_key()
{
    MPSS_SE_CloseKey(name().c_str());
}

} // namespace mpss::impl::os
