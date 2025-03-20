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

            // If the signature buffer is empty, return the size of the signature
            if (sig.empty()) {
                switch(info_.key_bits) {
                    case 256:
                        return 72;
                    case 384:
                        return 104;
                    case 512:
                        return 140;
                    default:
                        {
                            std::stringstream ss;
                            ss << "Unknown key bit size: " << info_.key_bits;
                            mpss::utils::set_error(ss.str());
                            return 0;
                        }
                }
            }

            std::size_t signature_size = sig.size();
            if (!SignHashMacOS(
                name_.c_str(),
                static_cast<int>(algorithm()),
                reinterpret_cast<const std::uint8_t *>(hash.data()),
                hash.size(),
                reinterpret_cast<std::uint8_t*>(sig.data()),
                &signature_size))
            {
                return 0;
            }

            return signature_size;
        }

        bool MacKeyPair::verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
        {
            return VerifySignatureMacOS(
                name_.c_str(),
                static_cast<int>(algorithm()),
                reinterpret_cast<const std::uint8_t *>(hash.data()),
                hash.size(),
                reinterpret_cast<const std::uint8_t *>(sig.data()),
                sig.size());
        }

        std::size_t MacKeyPair::extract_key(gsl::span<std::byte> public_key) const
        {
            if (public_key.empty()) {
                // return pk size
                switch(info_.key_bits) {
                    case 256:
                        return 65;
                    case 384:
                        return 97;
                    case 512:
                        return 133;
                    default: {
                        std::stringstream ss;
                        ss << "Unknown key bit size: " << info_.key_bits;
                        mpss::utils::set_error(ss.str());
                        return 0;
                    }
                }
            }

            std::size_t pk_size = public_key.size();

            if (!GetPublicKeyMacOS(
                name_.c_str(),
                reinterpret_cast<std::uint8_t*>(public_key.data()),
                &pk_size)) {
                return 0;
            }

            return pk_size;
        }

        void MacKeyPair::release_key()
        {
            RemoveKeyMacOS(name_.c_str());
        }
    }
}
