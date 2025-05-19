// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"
#include "mac_keypair.h"
#include "mac_api_wrapper.h"

namespace {
    constexpr const char *storage_description = "Keychain";
}

namespace mpss {
    namespace impl {
        MacKeyPair::MacKeyPair(std::string_view name, Algorithm algorithm)
            : KeyPair(algorithm, /* hardware_backed */ false, storage_description), name_(name)
        {}

        MacKeyPair::MacKeyPair(
            std::string_view name,
            Algorithm algorithm,
            bool hardware_backed,
            const char *storage_description)
            : KeyPair(algorithm, hardware_backed, storage_description), name_(name)
        {}

        MacKeyPair::~MacKeyPair()
        {
            release_key();
        }

        bool MacKeyPair::delete_key()
        {
            return do_delete_key();
        }

        std::size_t MacKeyPair::sign_hash(
            gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const
        {
            // If there is nothing to sign, return 0
            if (hash.empty()) {
                mpss::utils::set_error("Nothing to sign.");
                return 0;
            }

            if (hash.size() != info_.hash_bits / 8) {
                std::stringstream ss;
                ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits
                   << " bits)";
                mpss::utils::set_error(ss.str());
                return 0;
            }

            // If the signature buffer is empty, return the max size of the signature
            if (sig.empty()) {
                return mpss::utils::get_max_signature_length(algorithm());
            }

            return do_sign_hash(hash, sig);
        }

        bool MacKeyPair::verify(
            gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
        {
            // If there is nothing to verify, return false
            if (hash.empty() || sig.empty()) {
                mpss::utils::set_error("Nothing to verify.");
                return false;
            }

            if (hash.size() != info_.hash_bits / 8) {
                std::stringstream ss;
                ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits
                   << " bits)";
                mpss::utils::set_error(ss.str());
                return false;
            }

            return do_verify(hash, sig);
        }

        std::size_t MacKeyPair::extract_key(gsl::span<std::byte> public_key) const
        {
            if (public_key.empty()) {
                // return pk size
                return mpss::utils::get_public_key_size(algorithm());
            }

            return do_extract_key(public_key);
        }

        void MacKeyPair::release_key()
        {
            do_release_key();
        }

        bool MacKeyPair::do_delete_key()
        {
            bool result = MPSS_DeleteKey(name_.c_str());
            if (!result) {
                std::stringstream ss;
                ss << "Failed to delete key: " << MPSS_GetLastError();
                mpss::utils::set_error(ss.str());
            }

            return result;
        }

        std::size_t MacKeyPair::do_sign_hash(
            gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const
        {
            std::size_t signature_size = sig.size();

            if (!MPSS_SignHash(
                    name().c_str(),
                    static_cast<int>(algorithm()),
                    reinterpret_cast<const std::uint8_t *>(hash.data()),
                    hash.size(),
                    reinterpret_cast<std::uint8_t *>(sig.data()),
                    &signature_size)) {
                std::stringstream ss;
                ss << "Failed to sign hash: " << MPSS_GetLastError();
                mpss::utils::set_error(ss.str());
                return 0;
            }

            return signature_size;
        }

        bool MacKeyPair::do_verify(
            gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
        {
            bool result = MPSS_VerifySignature(
                name().c_str(),
                static_cast<int>(algorithm()),
                reinterpret_cast<const std::uint8_t *>(hash.data()),
                hash.size(),
                reinterpret_cast<const std::uint8_t *>(sig.data()),
                sig.size());
            if (!result) {
                std::stringstream ss;
                ss << "Failed to verify signature: " << MPSS_GetLastError();
                mpss::utils::set_error(ss.str());
            }

            return result;
        }

        std::size_t MacKeyPair::do_extract_key(gsl::span<std::byte> public_key) const
        {
            std::size_t pk_size = public_key.size();

            if (!MPSS_GetPublicKey(
                    name().c_str(),
                    reinterpret_cast<std::uint8_t *>(public_key.data()),
                    &pk_size)) {
                std::stringstream ss;
                ss << "Failed to retrieve public key: " << MPSS_GetLastError();
                mpss::utils::set_error(ss.str());
                return 0;
            }

            return pk_size;
        }

        void MacKeyPair::do_release_key()
        {
            MPSS_RemoveKey(name().c_str());
        }
    } // namespace impl
} // namespace mpss
