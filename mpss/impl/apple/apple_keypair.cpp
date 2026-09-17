// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/apple/apple_keypair.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

AppleKeyPairBase::AppleKeyPairBase(std::string_view name, Algorithm algorithm, bool hardware_backed,
                                   const char *storage_description)
    : KeyPair{algorithm, hardware_backed, storage_description}, name_{name}
{
}

void AppleKeyPairBase::release_key()
{
    // The cache entry is reference counted, so a second release would drop a hold this handle does
    // not own. Callers may release explicitly, and the destructor releases again.
    if (released_)
    {
        return;
    }
    released_ = true;

    do_release_key();
}

} // namespace mpss::impl::os
