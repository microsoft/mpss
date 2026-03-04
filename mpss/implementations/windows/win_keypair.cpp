// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/windows/win_keypair.h"
#include "mpss/implementations/windows/win_utils.h"
#include "mpss/utils/utilities.h"
#include <Windows.h>
#include <algorithm>
#include <memory>
#include <ncrypt.h>

namespace mpss::impl::os
{

bool WindowsKeyPair::delete_key()
{
    mpss::utils::log_trace("Deleting Windows key.");
    SECURITY_STATUS status = ::NCryptDeleteKey(key_handle_, /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptDeleteKey failed with error code {}.", mpss::utils::to_hex(status));
        return false;
    }

    // Release the key handle.
    win_release();

    mpss::utils::log_trace("Windows key deleted successfully.");
    return true;
}

std::size_t WindowsKeyPair::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    if (sig.empty())
    {
        // If the signature buffer is empty, we want to return the size of the signature.
        return mpss::utils::get_max_signature_size(algorithm());
    }

    mpss::utils::log_trace("Signing hash with Windows key, hash size {}.", hash.size());

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return 0;
    }
    if (!mpss::utils::check_sufficient_signature_buffer_size(sig, algorithm()))
    {
        return 0;
    }

    const std::size_t hash_bytes = hash.size();
    const DWORD hash_bytes_dw = mpss::utils::narrow_or_error<DWORD>(hash_bytes);
    if (0 == hash_bytes_dw)
    {
        return 0;
    }

    crypto_params const *const crypto = utils::get_crypto_params(algorithm());
    if (nullptr == crypto)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm()).type_str);
        return 0;
    }

    // Get the size of the raw signature.
    DWORD sig_size_dw = 0;
    SECURITY_STATUS status = ::NCryptSignHash(
        key_handle_,
        /* pPaddingInfo */ nullptr, reinterpret_cast<PBYTE>(const_cast<std::byte *>(hash.data())), hash_bytes_dw,
        /* pbSignature */ nullptr,
        /* cbSignature */ 0, &sig_size_dw,
        /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptSignHash to get signature size failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return 0;
    }

    // Get the actual signature.
    std::unique_ptr<BYTE[]> signature_buffer = std::make_unique<BYTE[]>(sig_size_dw);
    status = ::NCryptSignHash(key_handle_,
                              /* pPaddingInfo */ nullptr, reinterpret_cast<PBYTE>(const_cast<std::byte *>(hash.data())),
                              hash_bytes_dw, signature_buffer.get(), sig_size_dw, &sig_size_dw,
                              /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptSignHash failed with error code {}.", mpss::utils::to_hex(status));
        return 0;
    }

    // We need to reverse the signature bytes.
    const DWORD key_bytes = sig_size_dw / 2;
    std::unique_ptr<BYTE[]> reversed_signature_buffer = std::make_unique<BYTE[]>(sig_size_dw);
    std::span<BYTE> reversed_signature_span(reversed_signature_buffer.get(), sig_size_dw);
    std::copy(signature_buffer.get(), signature_buffer.get() + key_bytes, reversed_signature_span.rbegin() + key_bytes);
    std::copy(signature_buffer.get() + key_bytes, signature_buffer.get() + sig_size_dw,
              reversed_signature_span.rbegin());

    CERT_ECC_SIGNATURE eccSig{};
    eccSig.r.cbData = key_bytes;
    eccSig.r.pbData = reversed_signature_buffer.get();
    eccSig.s.cbData = key_bytes;
    eccSig.s.pbData = (reversed_signature_buffer.get() + key_bytes);

    DWORD encoded_size = 0;

    // Get the size of the encoding.
    if (!::CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ECC_SIGNATURE, &eccSig, 0 /* dwFlags */,
                               /* PCRYPT_ENCODE_PARA */ nullptr,
                               /* pvEncoded */ nullptr, &encoded_size))
    {
        mpss::utils::log_and_set_error("CryptEncodeObjectEx failed with error code {}.",
                                       mpss::utils::to_hex(::GetLastError()));
        return 0;
    }

    const std::size_t encoded_size_sz = mpss::utils::narrow_or_error<std::size_t>(encoded_size);
    if (0 == encoded_size_sz)
    {
        return 0;
    }

    // If the signature buffer is too small, return 0.
    if (sig.size() < encoded_size_sz)
    {
        mpss::utils::log_and_set_error("Signature buffer is too small. Expected {} bytes (got {} bytes).",
                                       encoded_size_sz, sig.size());
        return 0;
    }

    // Encode the signature.
    if (!::CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ECC_SIGNATURE, &eccSig, 0 /* dwFlags */,
                               /* PCRYPT_ENCODE_PARA */ nullptr, sig.data(), &encoded_size))
    {
        mpss::utils::log_and_set_error("CryptEncodeObjectEx failed with error code {}.",
                                       mpss::utils::to_hex(::GetLastError()));
        return 0;
    }

    // Return the number of bytes written to the signature buffer.
    const std::size_t result = mpss::utils::narrow_or_error<std::size_t>(encoded_size);
    mpss::utils::log_trace("Windows sign produced {} byte signature.", result);
    return result;
}

bool WindowsKeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    if (hash.empty() || sig.empty())
    {
        mpss::utils::log_warn("Nothing to verify.");
        return false;
    }

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return false;
    }

    const std::size_t hash_bytes = hash.size();
    const DWORD hash_bytes_dw = mpss::utils::narrow_or_error<DWORD>(hash_bytes);
    if (0 == hash_bytes_dw)
    {
        return false;
    }

    // Decode the signature.
    std::size_t raw_sig_size = utils::decode_raw_signature(sig, algorithm_, {});
    if (0 == raw_sig_size)
    {
        // This should not fail at this point unless the signature is invalid.
        return false;
    }

    std::unique_ptr<std::byte[]> raw_sig = std::make_unique<std::byte[]>(raw_sig_size);
    std::span<std::byte> raw_sig_span(raw_sig.get(), raw_sig_size);
    raw_sig_size = utils::decode_raw_signature(sig, algorithm_, raw_sig_span);
    if (0 == raw_sig_size)
    {
        // This should not fail at this point unless the signature is invalid.
        return false;
    }

    SECURITY_STATUS status = ::NCryptVerifySignature(
        key_handle_,
        /* pPaddingInfo */ nullptr, reinterpret_cast<PBYTE>(const_cast<std::byte *>(hash.data())), hash_bytes_dw,
        reinterpret_cast<PBYTE>(raw_sig_span.data()), raw_sig_size,
        /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        // This should not fail at this point unless the signature is invalid.
        return false;
    }

    return true;
}

std::size_t WindowsKeyPair::extract_key(std::span<std::byte> public_key) const
{
    if (public_key.empty())
    {
        return mpss::utils::get_public_key_size(algorithm());
    }
    else if (!mpss::utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }

    mpss::utils::log_trace("Extracting public key from Windows key.");

    crypto_params const *const crypto = utils::get_crypto_params(algorithm_);

    // Get the public key size.
    DWORD pk_blob_size = 0;
    SECURITY_STATUS status = ::NCryptExportKey(key_handle_,
                                               /* hExportKey */ 0, crypto->public_key_blob_name(),
                                               /* pParameterList */ nullptr,
                                               /* pbOutput */ nullptr,
                                               /* cbOutput */ 0, &pk_blob_size,
                                               /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        // This should not fail at this point.
        mpss::utils::log_and_set_error("NCryptExportKey failed with error code {}.", mpss::utils::to_hex(status));
        return 0;
    }

    // This function returns the size of the key blob, which includes a header followed by the
    // key. First check that the returned size is at least the size of the blob header.
    if (pk_blob_size < sizeof(crypto_params::key_blob_t))
    {
        mpss::utils::log_and_set_error("NCryptExportKey returned an invalid key size.");
        return 0;
    }

    // We add 1 to this. The reason is that the Windows API returns just the X and Y
    // coordinates of the point, whereas we prefer to return a standard format with
    // the point compression indicator. All returned points are uncompressed (0x04).
    std::size_t pk_size = pk_blob_size - sizeof(crypto_params::key_blob_t) + 1;

    // Actually get the key.
    auto pk_blob = std::make_unique<BYTE[]>(pk_blob_size);
    status = ::NCryptExportKey(key_handle_,
                               /* hExportKey */ 0, crypto->public_key_blob_name(),
                               /* pParameterList */ nullptr, pk_blob.get(), pk_blob_size, &pk_blob_size,
                               /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptExportKey failed with error code {}.", mpss::utils::to_hex(status));
        return 0;
    }

    crypto_params::key_blob_t *pk_blob_ptr = reinterpret_cast<crypto_params::key_blob_t *>(pk_blob.get());
    if (pk_blob_ptr->dwMagic != crypto->public_key_magic())
    {
        mpss::utils::log_and_set_error("Invalid public key magic.");
        return 0;
    }

    BYTE *pk_data_start = pk_blob.get() + sizeof(crypto_params::key_blob_t);
    BYTE *pk_data_end = pk_data_start + (pk_blob_size - sizeof(crypto_params::key_blob_t));

    // Check the input buffer is big enough
    const std::size_t pk_expected_size = pk_data_end - pk_data_start + 1;
    if (mpss::utils::get_public_key_size(algorithm()) != pk_expected_size)
    {
        mpss::utils::log_and_set_error("Unexpected public key size. Expected {} bytes, got {} bytes.", pk_expected_size,
                                       pk_expected_size);
        return 0;
    }

    // Write the compression indicator to the output buffer.
    public_key[0] = std::byte{0x04}; // Uncompressed point indicator.

    // Copy the public key data to the output buffer.
    std::transform(pk_data_start, pk_data_end, public_key.begin() + 1,
                   [](auto in) { return static_cast<std::byte>(in); });

    return pk_size;
}

void WindowsKeyPair::release_key() noexcept
{
    win_release();
}

void WindowsKeyPair::win_release() noexcept
{
    if (0 != key_handle_)
    {
        ::NCryptFreeObject(key_handle_);
    }

    clear_handle();
}

void WindowsKeyPair::clear_handle() noexcept
{
    key_handle_ = 0;
}

} // namespace mpss::impl::os
