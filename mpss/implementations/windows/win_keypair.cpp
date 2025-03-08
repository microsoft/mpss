// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/windows/win_keypair.h"
#include "mpss/implementations/windows/win_utils.h"
#include "mpss/utils/utilities.h"
#include "mpss/utils/scope_guard.h"

#include <algorithm>
#include <memory>
#include <string>
#include <sstream>

#include <Windows.h>
#include <ncrypt.h>

#include <gsl/narrow>

namespace mpss::impl {
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

    std::size_t WindowsKeyPair::sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const
    {
        // If there is nothing to sign, return 0 no matter what.
        if (hash.empty()) {
            utils::set_error(ERROR_INVALID_PARAMETER, "Nothing to sign.");
            return 0;
        }

        crypto_params const *const crypto = utils::get_crypto_params(algorithm());
        if (!crypto) {
            utils::set_error(ERROR_INTERNAL_ERROR, "Unsupported algorithm.");
            return 0;
        }

        if (hash.size() != info_.hash_bits / 8) {
            std::stringstream ss;
            ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits << " bits)";
            utils::set_error(ERROR_INVALID_PARAMETER, ss.str());
            return 0;
        }

        // Cast the hash size.
        DWORD hash_size = mpss::utils::narrow_or_error<DWORD>(hash.size());
        if (!hash_size) {
            return 0;
        }

        // Get the size of the signature.
        DWORD sig_size_dw = 0;
        SECURITY_STATUS status = ::NCryptSignHash(
            key_handle_,
            /* pPaddingInfo */ nullptr,
            reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
            hash_size,
            /* pbSignature */ nullptr,
            /* cbSignature */ 0,
            &sig_size_dw,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptSignHash to get signature size failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return 0;
        }

        // If the signature buffer is empty, return the size of the signature.
        std::size_t sig_size_sz = mpss::utils::narrow_or_error<std::size_t>(sig_size_dw);
        if (!sig_size_sz) {
            return 0;
        }
        if (sig.empty()) {
            return sig_size_sz;
        }

        // If the signature buffer is too small, return 0.
        if (sig.size() < sig_size_sz) {
            utils::set_error(ERROR_INSUFFICIENT_BUFFER, "Signature buffer is too small.");
            return 0;
        }

        DWORD sig_buf_size = mpss::utils::narrow_or_error<DWORD>(sig.size());
        if (!sig_buf_size) {
            return 0;
        }

        // Get the actual signature.
        status = ::NCryptSignHash(
            key_handle_,
            /* pPaddingInfo */ nullptr,
            reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
            hash_size,
            reinterpret_cast<PBYTE>(sig.data()),
            sig_buf_size,
            &sig_size_dw,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptSignHash failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return 0;
        }

        // Return the number of bytes written to the signature buffer.
        return mpss::utils::narrow_or_error<std::size_t>(sig_size_dw);
    }

    bool WindowsKeyPair::verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
    {
        // If either input is empty, return false and set an error.
        if (hash.empty() || sig.empty()) {
            utils::set_error(ERROR_INVALID_PARAMETER, "Nothing to verify.");
            return false;
        }

        if (hash.size() != info_.hash_bits / 8) {
            std::stringstream ss;
            ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits << " bits)";
            utils::set_error(ERROR_INVALID_PARAMETER, ss.str());
            return false;
        }

        DWORD hash_size = mpss::utils::narrow_or_error<DWORD>(hash.size());
        DWORD sig_size = mpss::utils::narrow_or_error<DWORD>(sig.size());
        if (!(hash_size | sig_size)) {
            return false;
        }

        SECURITY_STATUS status = ::NCryptVerifySignature(
            key_handle_,
            /* pPaddingInfo */ nullptr,
            reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
            hash_size,
            reinterpret_cast<PBYTE>(const_cast<std::byte*>(sig.data())),
            sig_size,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptVerifySignature failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return false;
        }

        return true;
    }

    std::size_t WindowsKeyPair::extract_key(gsl::span<std::byte> public_key) const
    {
        crypto_params const *const crypto = utils::get_crypto_params(algorithm());

        // Get the public key size.
        DWORD pk_blob_size = 0;
        SECURITY_STATUS status = ::NCryptExportKey(
            key_handle_,
            /* hExportKey */ 0,
            crypto->public_key_blob_name(),
            /* pParameterList */ nullptr,
            /* pbOutput */ nullptr,
            /* cbOutput */ 0,
            &pk_blob_size,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return 0;
        }

        // This function returns the size of the key blob, which includes a header followed by the key.
        // First check that the returned size is at least the size of the blob header.
        if (pk_blob_size < sizeof(crypto_params::key_blob_t)) {
            utils::set_error(ERROR_INTERNAL_ERROR, "NCryptExportKey returned an invalid key size.");
            return 0;
        }
        std::size_t pk_size = pk_blob_size - sizeof(crypto_params::key_blob_t);

        // If the verification key buffer is empty, return the size of the key.
        if (public_key.empty()) {
            return pk_size;
        }

        // Actually get the key.
        auto pk_blob = std::make_unique<BYTE[]>(pk_blob_size);
        status = ::NCryptExportKey(
            key_handle_,
            /* hExportKey */ 0,
            crypto->public_key_blob_name(),
            /* pParameterList */ nullptr,
            pk_blob.get(),
            pk_blob_size,
            &pk_blob_size,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
            utils::set_error(status, ss.str());
            return 0;
        }

        crypto_params::key_blob_t *pk_blob_ptr = reinterpret_cast<crypto_params::key_blob_t*>(pk_blob.get());
        if (pk_blob_ptr->dwMagic != crypto->public_key_magic()) {
            utils::set_error(status, "Invalid public key magic.");
            return 0;
        }

        BYTE *pk_data_start = pk_blob.get() + sizeof(crypto_params::key_blob_t);
        BYTE *pk_data_end = pk_data_start + pk_size;

        // Copy the public key data to the output buffer.
        std::transform(pk_data_start, pk_data_end, public_key.begin(), [](auto in) { return static_cast<std::byte>(in); });

        // Securely clear the blob, just to be nice, neat, and tidy.
        SecureZeroMemory(pk_blob.get(), pk_blob_size);

        return pk_size;
    }

    void WindowsKeyPair::release_key() noexcept
    {
        win_release();
    }

    void WindowsKeyPair::win_release() noexcept
    {
        if (key_handle_) {
            ::NCryptFreeObject(key_handle_);
        }

        clear_handle();
    }

    void WindowsKeyPair::clear_handle() noexcept
    {
        key_handle_ = 0;
    }
}
