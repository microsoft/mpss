// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mac_keypair.h"
#include "mac_api_wrapper.h"
#include "mac_se_wrapper.h"
#include "mac_utils.h"
#include "mpss/utils/utilities.h"

namespace mpss
{
    namespace impl
    {
        MacKeyPair::MacKeyPair(std::string_view name, Algorithm algorithm, bool secure_enclave)
            : KeyPair(algorithm), name_(name), secure_enclave_(secure_enclave)
        {
        }

        MacKeyPair::~MacKeyPair()
        {
            release_key();
        }

        bool MacKeyPair::delete_key()
        {
            bool result = false;
            if (secure_enclave_)
            {
                MPSS_SE_RemoveExistingKey(name_.c_str());
                result = true;
            }
            else
            {
                result = MPSS_DeleteKey(name_.c_str());
            }

            return result;
        }

        std::size_t MacKeyPair::sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const
        {
            // If there is nothing to sign, return 0
            if (hash.empty())
            {
                mpss::utils::set_error("Nothing to sign.");
                return 0;
            }

            if (hash.size() != info_.hash_bits / 8)
            {
                std::stringstream ss;
                ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits << " bits)";
                mpss::utils::set_error(ss.str());
                return 0;
            }

            // If the signature buffer is empty, return the size of the signature
            if (sig.empty())
            {
                return mpss::utils::get_max_signature_length(algorithm());
            }

            std::size_t signature_size = sig.size();

            if (secure_enclave_)
            {
                if (!MPSS_SE_Sign(name_.c_str(),
                                  reinterpret_cast<const std::uint8_t *>(hash.data()),
                                  hash.size(),
                                  reinterpret_cast<std::uint8_t *>(sig.data()),
                                  &signature_size))
                {

                    return 0;
                }
            }
            else
            {
                if (!MPSS_SignHash(
                        name_.c_str(),
                        static_cast<int>(algorithm()),
                        reinterpret_cast<const std::uint8_t *>(hash.data()),
                        hash.size(),
                        reinterpret_cast<std::uint8_t *>(sig.data()),
                        &signature_size))
                {
                    return 0;
                }
            }

            return signature_size;
        }

        bool MacKeyPair::verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
        {
            // If there is nothing to verify, return false
            if (hash.empty() || sig.empty())
            {
                mpss::utils::set_error("Nothing to verify.");
                return false;
            }

            if (hash.size() != info_.hash_bits / 8)
            {
                std::stringstream ss;
                ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits << " bits)";
                mpss::utils::set_error(ss.str());
                return false;
            }

            if (secure_enclave_)
            {
                bool result = MPSS_SE_VerifySignature(
                    name_.c_str(),
                    reinterpret_cast<const std::uint8_t *>(hash.data()),
                    hash.size(),
                    reinterpret_cast<const std::uint8_t *>(sig.data()),
                    sig.size());
                if (!result)
                {
                    std::stringstream ss;
                    ss << "Failed to verify signature: " << mpss::impl::utils::MPSS_SE_GetLastError();
                    mpss::utils::set_error(ss.str());
                }

                return result;
            }

            bool result = MPSS_VerifySignature(
                name_.c_str(),
                static_cast<int>(algorithm()),
                reinterpret_cast<const std::uint8_t *>(hash.data()),
                hash.size(),
                reinterpret_cast<const std::uint8_t *>(sig.data()),
                sig.size());
            if (!result)
            {
                std::stringstream ss;
                ss << "Failed to verify signature: " << MPSS_GetLastError();
                mpss::utils::set_error(ss.str());
            }

            return result;
        }

        std::size_t MacKeyPair::extract_key(gsl::span<std::byte> public_key) const
        {
            if (public_key.empty())
            {
                // return pk size
                return mpss::utils::get_public_key_size(algorithm());
            }

            std::size_t pk_size = public_key.size();

            if (secure_enclave_)
            {
                bool result = MPSS_SE_GetPublicKey(
                        name_.c_str(),
                        reinterpret_cast<std::uint8_t *>(public_key.data()),
                        &pk_size);
                if (!result)
                {
                    std::stringstream ss;
                    ss << "Failed to retrieve public key: " << mpss::impl::utils::MPSS_SE_GetLastError();
                    mpss::utils::set_error(ss.str());
                    return 0;
                }

                return pk_size;
            }

            if (!MPSS_GetPublicKey(
                    name_.c_str(),
                    reinterpret_cast<std::uint8_t *>(public_key.data()),
                    &pk_size))
            {
                std::stringstream ss;
                ss << "Failed to retrieve public key: " << MPSS_GetLastError();
                mpss::utils::set_error(ss.str());
                return 0;
            }

            return pk_size;
        }

        void MacKeyPair::release_key()
        {
            if (secure_enclave_)
            {
                MPSS_SE_CloseKey(name_.c_str());
            }
            else
            {
                MPSS_RemoveKey(name_.c_str());
            }
        }
    }
}
