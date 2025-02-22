// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include "mac_keypair.h"
#include "mac_api_wrapper.h"

namespace mpss
{
    namespace impl
    {
        std::unique_ptr<KeyPair> create_key(std::string_view name, SignatureAlgorithm algorithm)
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
                SignatureAlgorithm algorithm = SignatureAlgorithm::Undefined;
                switch (bitSize)
                {
                case 256:
                    algorithm = SignatureAlgorithm::ECDSA_P256_SHA256;
                    break;
                case 384:
                    algorithm = SignatureAlgorithm::ECDSA_P384_SHA384;
                    break;
                case 521:
                    algorithm = SignatureAlgorithm::ECDSA_P521_SHA512;
                    break;
                default:
                    std::string msg = "Unsupported key size: " + std::to_string(bitSize);
                    throw std::runtime_error(msg);
                }

                return std::make_unique<MacKeyPair>(name, algorithm);
            }

            return {};
        }

        bool is_safe_storage_supported(SignatureAlgorithm algorithm)
        {
            return false;
        }

        std::string get_error()
        {
            return "Yikes!";
        }
    }
}
