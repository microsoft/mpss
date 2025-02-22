// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mac_keypair.h"
#include "mac_api_wrapper.h"

namespace mpss
{
    namespace impl
    {
        MacKeyPair::MacKeyPair(std::string_view name, SignatureAlgorithm algorithm)
            : KeyPair(name, algorithm)
        {
        }

        MacKeyPair::~MacKeyPair()
        {
            release_key();
        }

        bool MacKeyPair::delete_key()
        {
            return DeleteKeyMacOS(name().data());
        }

        std::optional<std::vector<std::byte>> MacKeyPair::sign(gsl::span<std::byte> hash) const
        {
            std::size_t signature_size = 0;
            std::uint8_t *signature = nullptr;
            if (!SignHashMacOS(name().data(), static_cast<int>(algorithm()), reinterpret_cast<std::uint8_t *>(hash.data()), hash.size(), &signature, &signature_size))
            {
                return std::nullopt;
            }

            std::vector<std::byte> signature_vector(
                reinterpret_cast<std::byte *>(signature),
                reinterpret_cast<std::byte *>(signature + signature_size));

            return std::make_optional(std::move(signature_vector));
        }

        bool MacKeyPair::verify(gsl::span<std::byte> hash, gsl::span<std::byte> signature) const
        {
            return VerifySignatureMacOS(
                name().data(),
                static_cast<int>(algorithm()),
                reinterpret_cast<std::uint8_t *>(hash.data()),
                hash.size(),
                reinterpret_cast<std::uint8_t *>(signature.data()),
                signature.size());
        }

        bool MacKeyPair::get_verification_key(std::vector<std::byte> &vk_out) const
        {
            return false;
        }

        void MacKeyPair::release_key()
        {
            RemoveKeyMacOS(name().data());
        }
    }
}
