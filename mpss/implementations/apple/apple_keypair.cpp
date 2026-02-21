// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/apple/apple_keypair.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

AppleKeyPairBase::AppleKeyPairBase(std::string_view name, Algorithm algorithm, bool hardware_backed,
                                   const char *storage_description)
    : KeyPair{algorithm, hardware_backed, storage_description}, name_{name}
{
}

bool AppleKeyPairBase::delete_key()
{
    return do_delete_key();
}

std::size_t AppleKeyPairBase::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    if (sig.empty())
    {
        // If the signature buffer is empty, we want to return the size of the signature.
        return mpss::utils::get_max_signature_size(algorithm());
    }

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return 0;
    }
    if (!mpss::utils::check_sufficient_signature_buffer_size(sig, algorithm()))
    {
        return 0;
    }

    // do_sign_hash expects its inputs to be validated so that the signature buffer is large enough to hold the
    // signature and the hash is of the correct size.
    return do_sign_hash(hash, sig);
}

bool AppleKeyPairBase::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    if (hash.empty() || sig.empty())
    {
        mpss::utils::log_warn("Nothing to verify.");
        return false;
    }

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return false;
    }

    // do_verify expects its inputs to be of validated so that both inputs are non-empty and the hash is of the
    // correct size.
    return do_verify(hash, sig);
}

std::size_t AppleKeyPairBase::extract_key(std::span<std::byte> public_key) const
{
    if (public_key.empty())
    {
        return mpss::utils::get_public_key_size(algorithm());
    }
    else if (!mpss::utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }

    return do_extract_key(public_key);
}

void AppleKeyPairBase::release_key()
{
    do_release_key();
}

} // namespace mpss::impl::os
