// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include "mac_keypair.h"
#include "mac_se_keypair.h"
#include "mac_api_wrapper.h"
#include "mac_se_wrapper.h"
#include "mac_utils.h"

namespace mpss
{
    namespace impl
    {
        std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
        {
            std::string key_name(name);
            if (key_name.empty())
            {
                mpss::utils::set_error("Key name cannot be empty.");
                return {};
            }

            if (MPSS_SE_SecureEnclaveIsSupported() && algorithm == Algorithm::ecdsa_secp256r1_sha256)
            {
                // Secure Enclave only supports ECDSA P256
                if (MPSS_SE_CreateKey(key_name.c_str()))
                {
                    return std::make_unique<MacSEKeyPair>(name, algorithm);
                }

                std::stringstream ss;
                ss << "Failed to create key in Secure Enclave: " << mpss::impl::utils::MPSS_SE_GetLastError();
                mpss::utils::set_error(ss.str());
                return {};
            }

            if (MPSS_CreateKey(key_name.c_str(), static_cast<int>(algorithm)))
            {
                return std::make_unique<MacKeyPair>(name, algorithm);
            }

            std::stringstream ss;
            ss << "Failed to create key: " << MPSS_GetLastError();
            mpss::utils::set_error(ss.str());
            return {};
        }

        std::unique_ptr<KeyPair> open_key(std::string_view name)
        {
            std::string key_name(name);
            if (key_name.empty())
            {
                mpss::utils::set_error("Key name cannot be empty.");
                return {};
            }

            // Try secure enclave first if available
            if (MPSS_SE_SecureEnclaveIsSupported() && MPSS_SE_OpenExistingKey(key_name.c_str()))
            {
                return std::make_unique<MacSEKeyPair>(name, Algorithm::ecdsa_secp256r1_sha256);
            }

            int bitSize = 0;
            if (MPSS_OpenExistingKey(name.data(), &bitSize))
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
            if (hash.empty() || public_key.empty() || sig.empty())
            {
                mpss::utils::set_error("Hash, public key, and signature cannot be empty.");
                return false;
            }

            if (algorithm == Algorithm::unsupported)
            {
                mpss::utils::set_error("Unsupported algorithm.");
                return false;
            }

            // Check hash length
            if (!mpss::utils::check_hash_length(hash, algorithm)) {
                mpss::utils::set_error("Invalid hash length for algorithm");
                return false;
            }

            if (MPSS_SE_SecureEnclaveIsSupported() && algorithm == Algorithm::ecdsa_secp256r1_sha256)
            {
                // Secure Enclave only supports ECDSA P256
                bool result = MPSS_SE_VerifyStandaloneSignature(
                    reinterpret_cast<const std::uint8_t *>(public_key.data()),
                    public_key.size(),
                    reinterpret_cast<const std::uint8_t *>(hash.data()),
                    hash.size(),
                    reinterpret_cast<const std::uint8_t *>(sig.data()),
                    sig.size());
                if (!result)
                {
                    std::stringstream ss;
                    ss << "Failed to verify standalone signature: " << mpss::impl::utils::MPSS_SE_GetLastError();
                    mpss::utils::set_error(ss.str());
                }

                return result;
            }

            bool result = MPSS_VerifyStandaloneSignature(
                static_cast<int>(algorithm),
                reinterpret_cast<const std::uint8_t *>(hash.data()),
                hash.size(),
                reinterpret_cast<const std::uint8_t *>(public_key.data()),
                public_key.size(),
                reinterpret_cast<const std::uint8_t *>(sig.data()),
                sig.size());
            if (!result)
            {
                std::stringstream ss;
                ss << "Failed to verify standalone signature: " << MPSS_GetLastError();
                mpss::utils::set_error(ss.str());
            }

            return result;
        }
    }
}
