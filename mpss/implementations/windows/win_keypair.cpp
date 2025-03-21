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
    using mpss::utils::set_error;
    using mpss::utils::to_hex;

    bool WindowsKeyPair::delete_key()
    {
        SECURITY_STATUS status = ::NCryptDeleteKey(key_handle_, /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptDeleteKey failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
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
            mpss::utils::set_error("Nothing to sign.");
            return 0;
        }

        if (sig.empty()) {
            // If the signature buffer is empty, we want to return the size of the signature.
            return mpss::utils::get_max_signature_length(algorithm());
        }

        crypto_params const *const crypto = utils::get_crypto_params(algorithm());
        if (!crypto) {
            mpss::utils::set_error("Unsupported algorithm.");
            return 0;
        }

        if (hash.size() != info_.hash_bits / 8) {
            std::stringstream ss;
            ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits << " bits)";
            mpss::utils::set_error(ss.str());
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
            mpss::utils::set_error(ss.str());
            return 0;
        }

        // Get the buffer for the signature
        std::unique_ptr<BYTE[]> signature_buffer = std::make_unique<BYTE[]>(sig_size_dw);
        if (!signature_buffer) {
            mpss::utils::set_error("Failed to allocate signature buffer.");
            return 0;
        }

        SCOPE_GUARD({
            // Zero out the signature buffer.
            ::SecureZeroMemory(signature_buffer.get(), sig_size_dw);
            });

        // Get the actual signature.
        DWORD signed_size = 0;
        status = ::NCryptSignHash(
            key_handle_,
            /* pPaddingInfo */ nullptr,
            reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
            hash_size,
            signature_buffer.get(),
            sig_size_dw,
            &signed_size,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptSignHash failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return 0;
        }

        CERT_ECC_SIGNATURE eccSig;
        DWORD field_size = signed_size / 2;
        eccSig.r.cbData = field_size;
        eccSig.r.pbData = signature_buffer.get();
        eccSig.s.cbData = field_size;
        eccSig.s.pbData = (signature_buffer.get() + field_size);

        DWORD encoded_size = 0;

        // Get the size of the encoding
        if (!::CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            &eccSig,
            /* dwFlags */ 0,
            /* PCRYPT_ENCODE_PARA */ nullptr,
            /* pvEncoded */ nullptr,
            &encoded_size)) {
            std::stringstream ss;
            ss << "CryptEncodeObjectEx failed with error code " << mpss::utils::to_hex(::GetLastError());
            mpss::utils::set_error(ss.str());
            return 0;
        }

        std::size_t encoded_size_sz = mpss::utils::narrow_or_error<std::size_t>(encoded_size);
        if (!encoded_size_sz) {
            return 0;
        }

        // If the signature buffer is too small, return 0.
        if (sig.size() < encoded_size_sz) {
			std::stringstream ss;
			ss << "Signature buffer is too small. Expected " << encoded_size_sz << " bytes, got " << sig.size() << " bytes.";
            mpss::utils::set_error(ss.str());
            return 0;
        }

        // Encode the signature.
        if (!::CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            &eccSig,
            /* dwFlags */ 0,
            /* PCRYPT_ENCODE_PARA */ nullptr,
            sig.data(),
            &encoded_size)) {
            std::stringstream ss;
            ss << "CryptEncodeObjectEx failed with error code " << mpss::utils::to_hex(::GetLastError());
            mpss::utils::set_error(ss.str());
            return 0;
        }

        // Return the number of bytes written to the signature buffer.
        return mpss::utils::narrow_or_error<std::size_t>(encoded_size);
    }

    bool WindowsKeyPair::verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
    {
        // If either input is empty, return false and set an error.
        if (hash.empty() || sig.empty()) {
            mpss::utils::set_error("Nothing to verify.");
            return false;
        }

		DWORD field_size = mpss::utils::narrow_or_error<DWORD>((info_.key_bits + 7) / 8);
		if (field_size == 0) {
			return false;
		}

        // Decode signature
		DWORD encoded_size = mpss::utils::narrow_or_error<DWORD>(sig.size());
		if (encoded_size == 0) {
			return false;
		}

        // Get required decoded size
        DWORD ecc_sig_buffer_size = 0;
        if (!::CryptDecodeObjectEx(
			X509_ASN_ENCODING,
			X509_ECC_SIGNATURE,
            reinterpret_cast<LPCBYTE>(sig.data()),
            encoded_size,
			/* dwFlags */ 0,
			/* PCRYPT_DECODE_PARA */ nullptr,
			/* pvStructInfo */ nullptr,
			&ecc_sig_buffer_size)) {
			std::stringstream ss;
			ss << "CryptDecodeObjectEx failed with error code " << mpss::utils::to_hex(::GetLastError());
			mpss::utils::set_error(ss.str());
			return false;
		}

		std::unique_ptr<BYTE[]> ecc_sig_buffer = std::make_unique<BYTE[]>(ecc_sig_buffer_size);
		if (!ecc_sig_buffer) {
			mpss::utils::set_error("Failed to allocate signature buffer.");
			return false;
		}
		SCOPE_GUARD({
			// Zero out the signature buffer.
			::SecureZeroMemory(ecc_sig_buffer.get(), ecc_sig_buffer_size);
			});

		// Decode the signature
        if (!::CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            reinterpret_cast<LPCBYTE>(sig.data()),
            encoded_size,
            /* dwFlags */ 0,
            /* PCRYPT_DECODE_PARA */ nullptr,
            ecc_sig_buffer.get(),
            &ecc_sig_buffer_size)) {
            std::stringstream ss;
            ss << "CryptDecodeObjectEx failed with error code " << mpss::utils::to_hex(::GetLastError());
            mpss::utils::set_error(ss.str());
            return false;
        }

		CERT_ECC_SIGNATURE* ecc_sig = reinterpret_cast<CERT_ECC_SIGNATURE*>(ecc_sig_buffer.get());

		// Get raw signature data
        DWORD raw_sig_size = ecc_sig->r.cbData + ecc_sig->s.cbData;
		std::unique_ptr<BYTE[]> raw_signature = std::make_unique<BYTE[]>(raw_sig_size);
        if (!raw_signature) {
            mpss::utils::set_error("Failed to allocate signature buffer.");
            return false;
        }

		SCOPE_GUARD({
			// Zero out the raw signature buffer.
			::SecureZeroMemory(raw_signature.get(), raw_sig_size);
			});
		std::copy_n(ecc_sig->r.pbData, ecc_sig->r.cbData, raw_signature.get());
		std::copy_n(ecc_sig->s.pbData, ecc_sig->s.cbData, raw_signature.get() + ecc_sig->r.cbData);

        if (hash.size() != info_.hash_bits / 8) {
            std::stringstream ss;
            ss << "Invalid hash length " << hash.size() << " (expected " << info_.hash_bits << " bits)";
            mpss::utils::set_error(ss.str());
            return false;
        }

        DWORD hash_size = mpss::utils::narrow_or_error<DWORD>(hash.size());
        if (!hash_size) {
            return false;
        }

        SECURITY_STATUS status = ::NCryptVerifySignature(
            key_handle_,
            /* pPaddingInfo */ nullptr,
            reinterpret_cast<PBYTE>(const_cast<std::byte*>(hash.data())),
            hash_size,
            raw_signature.get(),
            raw_sig_size,
            /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptVerifySignature failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return false;
        }

        return true;
    }

    std::size_t WindowsKeyPair::extract_key(gsl::span<std::byte> public_key) const
    {
		// If the public key buffer is empty, return the size of the key.
        if (public_key.empty()) {
            return mpss::utils::get_public_key_size(algorithm());
        }

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
            mpss::utils::set_error(ss.str());
            return 0;
        }

        // This function returns the size of the key blob, which includes a header followed by the key.
        // First check that the returned size is at least the size of the blob header.
        if (pk_blob_size < sizeof(crypto_params::key_blob_t)) {
            mpss::utils::set_error("NCryptExportKey returned an invalid key size.");
            return 0;
        }

        // We add 1 to this. The reason is that the Windows API returns just the X and Y
        // coordinates of the point, whereas we prefer to return a standard format with
        // the point compression indicator. All returned points are uncompressed (0x04).
        std::size_t pk_size = pk_blob_size - sizeof(crypto_params::key_blob_t) + 1;

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
            mpss::utils::set_error(ss.str());
            return 0;
        }

        crypto_params::key_blob_t *pk_blob_ptr = reinterpret_cast<crypto_params::key_blob_t*>(pk_blob.get());
        if (pk_blob_ptr->dwMagic != crypto->public_key_magic()) {
            mpss::utils::set_error("Invalid public key magic.");
            return 0;
        }

        BYTE *pk_data_start = pk_blob.get() + sizeof(crypto_params::key_blob_t);
        BYTE *pk_data_end = pk_data_start + (pk_blob_size - sizeof(crypto_params::key_blob_t));

        // Check the input buffer is big enough
        if (public_key.size() < (pk_data_end - pk_data_start + 1)) {
			std::stringstream ss;
			ss << "Public key buffer is too small. Expected " << (pk_data_end - pk_data_start + 1) << " bytes, got " << public_key.size() << " bytes.";
			mpss::utils::set_error(ss.str());
			return 0;
        }

        // Write the compression indicator to the output buffer.
        public_key[0] = std::byte{ 0x04 }; // Uncompressed point indicator.

        // Copy the public key data to the output buffer.
        std::transform(pk_data_start, pk_data_end, public_key.begin() + 1, [](auto in) { return static_cast<std::byte>(in); });

        // Securely clear the blob, just to be nice, neat, and tidy.
        ::SecureZeroMemory(pk_blob.get(), pk_blob_size);

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
