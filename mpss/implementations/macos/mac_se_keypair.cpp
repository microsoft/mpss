// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mac_se_keypair.h"
#include "mac_se_wrapper.h"
#include "mac_utils.h"
#include "mpss/utils/utilities.h"

namespace {
    constexpr const char* storage_description = "Secure Enclave";
}

namespace mpss
{
    namespace impl
    {
        MacSEKeyPair::MacSEKeyPair(std::string_view name, Algorithm algorithm)
            : MacKeyPair(name, algorithm, /* hardware_backed */ true, storage_description) 
        {
        }

        MacSEKeyPair::~MacSEKeyPair()
        {
            // No need to release the key here, as it is managed by the base class
        }

        bool MacSEKeyPair::do_delete_key()
        {
            MPSS_SE_RemoveExistingKey(name().c_str());
            return true;
        }

        std::size_t MacSEKeyPair::do_sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const
        {
            std::size_t signature_size = sig.size();

            if (!MPSS_SE_Sign(name().c_str(),
                              reinterpret_cast<const std::uint8_t *>(hash.data()),
                              hash.size(),
                              reinterpret_cast<std::uint8_t *>(sig.data()),
                              &signature_size))
            {
                std::stringstream ss;
                ss << "Failed to sign hash: " << mpss::impl::utils::MPSS_SE_GetLastError();
                mpss::utils::set_error(ss.str());
                return 0;
            }

            return signature_size;
        }

        bool MacSEKeyPair::do_verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
        {
            bool result = MPSS_SE_VerifySignature(
                name().c_str(),
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

        std::size_t MacSEKeyPair::do_extract_key(gsl::span<std::byte> public_key) const
        {
            std::size_t pk_size = public_key.size();

            bool result = MPSS_SE_GetPublicKey(
                name().c_str(),
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

        void MacSEKeyPair::do_release_key()
        {
            MPSS_SE_CloseKey(name().c_str());
        }
    }
}
