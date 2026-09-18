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

} // namespace mpss::impl::os
