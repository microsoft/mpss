// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mac_keypair.h"
#include "mac_api_wrapper.h"
#include "mpss/utils/utilities.h"

namespace mpss
{
    namespace impl
    {
        MacKeyPair::MacKeyPair(std::string_view name, Algorithm algorithm)
            : KeyPair(algorithm), name_(name)
        {
        }

        MacKeyPair::~MacKeyPair()
        {
            release_key();
        }

        bool MacKeyPair::delete_key()
        {
            return DeleteKeyMacOS(name_.c_str());
        }

        std::size_t MacKeyPair::sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const
        {
            // If there is nothing to sign, return 0
            if (hash.empty()) {
                mpss::utils::set_error("Nothing to sign.");
                return 0;
            }

            if (hash.size() != info_.hash_bits / 8) {
                std::stringstream ss;
                ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits << " bits)";
                mpss::utils::set_error(ss.str());
                return 0;
            }

            // Cast the hash size
            
            std::size_t signature_size = 0;
            std::uint8_t *signature = nullptr;
            if (!SignHashMacOS(name().data(), static_cast<int>(algorithm()), reinterpret_cast<std::uint8_t *>(hash.data()), hash.size(), &signature, &signature_size))
            {
                return std::nullopt;
            }

            std::vector<std::byte> signature_vector(
                reinterpret_cast<std::byte *>(signature),
                reinterpret_cast<std::byte *>(signature + signature_size));

            // Signature memory was created with malloc
            free(signature);

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
            std::size_t pk_size = 0;
            std::uint8_t *pkData = nullptr;

            if (!GetPublicKeyMacOS(name().data(), &pkData, &pk_size)) {
                return false;
            }

            // Copy PK data
            vk_out.resize(pk_size);
            memcpy(vk_out.data(), pkData, pk_size);

            // PK data buffer was allocated with malloc
            free(pkData);

            return true;
        }

        void MacKeyPair::release_key()
        {
            RemoveKeyMacOS(name().data());
        }
    }
}
