// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mac_keypair.h"

namespace mpss {
    namespace impl {
        bool MacKeyPair::delete_key()
        {
            return false;
        }

        std::optional<std::vector<std::byte>> MacKeyPair::sign(gsl::span<std::byte> hash) const
        {
            return {};
        }

        bool MacKeyPair::verify(gsl::span<std::byte> hash, gsl::span<std::byte> signature) const
        {
            return false;
        }

        bool MacKeyPair::get_verification_key(std::vector<std::byte>& vk_out) const
        {
            return false;
        }

        void MacKeyPair::release_key()
        {
        }
    }
}