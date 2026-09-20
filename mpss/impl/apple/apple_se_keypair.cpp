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

AppleSEKeyPair::AppleSEKeyPair(std::string_view name, Algorithm algorithm, std::uint64_t generation)
    : AppleKeyPairBase{name, algorithm, /* hardware_backed */ true, storage_description, generation}
{
}

AppleSEKeyPair::~AppleSEKeyPair()
{
    release_from_destructor();
}

bool AppleSEKeyPair::do_delete_key()
{
    mpss::utils::log_trace("Deleting Secure Enclave key '{}'.", name());

    // Deleting reaches the name rather than the entry this handle opened, so refuse once the name
    // has moved on. Otherwise a handle to a deleted key would delete the key that replaced it.
    if (!MPSS_SE_GenerationIsCurrent(name().c_str(), generation()))
    {
        mpss::utils::log_and_set_error("Key '{}' is no longer the key this handle opened.", name());
        return false;
    }

    if (!utils::delete_key_from_all_tiers(name()))
    {
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
                      reinterpret_cast<std::uint8_t *>(sig.data()), &signature_size, generation()))
    {
        utils::report_secure_enclave_error("sign hash");
        return 0;
    }

    mpss::utils::log_trace("Secure Enclave sign produced {} byte signature.", signature_size);
    return signature_size;
}

bool AppleSEKeyPair::do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    const std::int32_t raw_result =
        MPSS_SE_VerifySignature(name().c_str(), reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
                                reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size(), generation());
    return utils::handle_secure_enclave_verification_result(raw_result, "verify signature");
}

std::size_t AppleSEKeyPair::do_extract_key(std::span<std::byte> public_key) const
{
    mpss::utils::log_trace("Extracting public key from Secure Enclave key '{}'.", name());
    std::size_t pk_size = public_key.size();

    const bool result = MPSS_SE_GetPublicKey(name().c_str(), reinterpret_cast<std::uint8_t *>(public_key.data()),
                                             &pk_size, generation());
    if (!result)
    {
        utils::report_secure_enclave_error("retrieve public key");
        return 0;
    }

    mpss::utils::log_trace("Extracted {} byte public key from Secure Enclave key '{}'.", pk_size, name());
    return pk_size;
}

bool AppleSEKeyPair::do_release_key()
{
    // Gives up a hold on an in-memory cache entry, which cannot fail.
    MPSS_SE_CloseKey(name().c_str(), generation());
    return true;
}

} // namespace mpss::impl::os
