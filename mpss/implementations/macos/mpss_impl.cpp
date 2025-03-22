// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include "mac_keypair.h"
#include "mac_api_wrapper.h"

namespace mpss
{
    namespace impl
    {
        std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
        {
            if (CreateKeyMacOS(name.data(), static_cast<int>(algorithm)))
            {
                return std::make_unique<MacKeyPair>(name, algorithm);
            }

            return {};
        }

        std::unique_ptr<KeyPair> open_key(std::string_view name)
        {
            int bitSize = 0;
            if (OpenExistingKeyMacOS(name.data(), &bitSize))
            {
                Algorithm algorithm = Algorithm::unsupported;
                switch (bitSize)
                {
                case 256:
                    algorithm = Algorithm::ecdsa_secp256r1_sha256;
                    break;
                case 384:
                    algorithm = Algorithm::ecdsa_secp384r1_sha384;
                    break;
                case 521:
                    algorithm = Algorithm::ecdsa_secp521r1_sha512;
                    break;
                default:
                    std::string msg = "Unsupported key size: " + std::to_string(bitSize);
                    throw std::runtime_error(msg);
                }

                return std::make_unique<MacKeyPair>(name, algorithm);
            }

            return {};
        }

        bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> public_key, Algorithm algorithm, gsl::span<const std::byte> sig)
        {
            return false;
        }
    }
}
