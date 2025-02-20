// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string>
#include <sstream>

#include "win_keypair.h"
#include "win_utils.h"
#include "mpss/utils/utilities.h"
#include "mpss/utils/scope_guard.h"


namespace mpss {
    namespace impl {
        bool WindowsKeyPair::delete_key()
        {
            SECURITY_STATUS status = ::NCryptDeleteKey(key_handle_, /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptDeleteKey failed with error code " << mpss::utils::to_hex(status);
                utils::set_error(status, ss.str());
                return false;
            }

            // Release the key handle.
            win_release();

            return true;
        }

        std::optional<std::vector<std::byte>> WindowsKeyPair::sign(gsl::span<std::byte> hash) const
        {
            std::vector<std::byte> signature;
            const crypto_params& crypto = utils::GetCryptoParams(algorithm());

            if (!mpss::utils::verify_hash_length(hash, algorithm())) {
                std::stringstream ss;
                ss << "Invalid hash length for algorithm. Length is: " << hash.size();
                utils::set_error(ERROR_INVALID_PARAMETER, ss.str());
                return std::nullopt;
            }

            DWORD signature_size = 0;

            // Get signature size.
            SECURITY_STATUS status = ::NCryptSignHash(
                key_handle_,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
                hash.size(),
                /* pbSignature */ nullptr,
                /* cbSignature */ 0,
                &signature_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSignHash to get signature size failed with error code " << mpss::utils::to_hex(status);
                utils::set_error(status, ss.str());
                return std::nullopt;
            }

            // Get the actual signature.
            signature.resize(signature_size);
            status = ::NCryptSignHash(
                key_handle_,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
                hash.size(),
                reinterpret_cast<PBYTE>(&signature[0]),
                static_cast<DWORD>(signature.size()),
                &signature_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSignHash failed with error code " << mpss::utils::to_hex(status);
                utils::set_error(status, ss.str());
                return std::nullopt;
            }

            return std::make_optional(signature);
        }

        bool WindowsKeyPair::verify(gsl::span<std::byte> hash, gsl::span<std::byte> signature) const
        {
            if (!mpss::utils::verify_hash_length(hash, algorithm())) {
                std::stringstream ss;
                ss << "Invalid hash length for algorithm. Length is: " << hash.size();
                utils::set_error(ERROR_INVALID_PARAMETER, ss.str());
                return false;
            }

            SECURITY_STATUS status = ::NCryptVerifySignature(
                key_handle_,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
                hash.size(),
                reinterpret_cast<PBYTE>(const_cast<std::byte*>(signature.data())),
                static_cast<DWORD>(signature.size()),
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptVerifySignature failed with error code " << mpss::utils::to_hex(status);
                utils::set_error(status, ss.str());
                return false;
            }

            return true;
        }

        bool WindowsKeyPair::get_verification_key(std::vector<std::byte>& vk_out) const
        {
            const crypto_params& crypto = utils::GetCryptoParams(algorithm());

            // Get the public key size.
            DWORD public_key_size = 0;
            SECURITY_STATUS status = ::NCryptExportKey(
                key_handle_,
                /* hExportKey */ 0,
                crypto.get_public_key_blob_name(),
                /* pParameterList */ nullptr,
                /* pbOutput */ nullptr,
                /* cbOutput */ 0,
                &public_key_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                utils::set_error(status, ss.str());
                return false;
            }

            // Actually get the public key
            BYTE* public_key_ptr = new BYTE[public_key_size];
            SCOPE_GUARD(delete[] public_key_ptr);

            status = ::NCryptExportKey(
                key_handle_,
                /* hExportKey */ 0,
                crypto.get_public_key_blob_name(),
                /* pParameterList */ nullptr,
                public_key_ptr,
                public_key_size,
                &public_key_size,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                utils::set_error(status, ss.str());
                return false;
            }

            crypto_params::key_blob_t* public_key_blob_ptr = reinterpret_cast<crypto_params::key_blob_t*>(public_key_ptr);
            if (public_key_blob_ptr->dwMagic != crypto.get_public_key_magic()) {
                utils::set_error(status, "Invalid public key magic");
                return false;
            }

            BYTE* data_start_ptr = reinterpret_cast<BYTE*>(public_key_blob_ptr) + sizeof(crypto_params::key_blob_t);
            vk_out.assign(
                reinterpret_cast<std::byte*>(data_start_ptr),
                reinterpret_cast<std::byte*>(data_start_ptr) + public_key_size - sizeof(crypto_params::key_blob_t));

            return true;
        }

        void WindowsKeyPair::release_key()
        {
            win_release();
        }

        void WindowsKeyPair::win_release()
        {
            if (key_handle_) {
                ::NCryptFreeObject(key_handle_);
            }

            clear_handle();
        }

        void WindowsKeyPair::clear_handle()
        {
            key_handle_ = 0;
        }
    }
}
