// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/windows/win_utils.h"
#include "mpss/utils/utilities.h"
#include <Windows.h>
#include <algorithm>
#include <ncrypt.h>

namespace
{

// Instantiating the crypto_params for each algorithm.
constexpr mpss::impl::os::ECDSA_P256 ecdsa_p256;
constexpr mpss::impl::os::ECDSA_P384 ecdsa_p384;
constexpr mpss::impl::os::ECDSA_P521 ecdsa_p521;

} // namespace

namespace mpss::impl::os::utils
{

using enum mpss::Algorithm;

crypto_params const *get_crypto_params(Algorithm algorithm) noexcept
{
    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        return &ecdsa_p256;
    case ecdsa_secp384r1_sha384:
        return &ecdsa_p384;
    case ecdsa_secp521r1_sha512:
        return &ecdsa_p521;
    default:
        return nullptr;
    }
}

std::size_t decode_raw_signature(std::span<const std::byte> der_sig, Algorithm algorithm,
                                 std::span<std::byte> raw_sig) noexcept
{
    // Check for obvious problems.
    if (der_sig.empty())
    {
        mpss::utils::log_warning("Nothing to decode.");
        return 0;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warning("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return 0;
    }

    if (raw_sig.empty())
    {
        // If the signature buffer is empty, we want to return the size of the signature.
        return mpss::utils::get_max_signature_size(algorithm);
    }

    if (!mpss::utils::check_sufficient_signature_buffer_size(raw_sig, algorithm))
    {
        return 0;
    }

    // Decode signature.
    const DWORD encoded_size = mpss::utils::narrow_or_error<DWORD>(der_sig.size());
    if (0 == encoded_size)
    {
        return 0;
    }

    // Get required decoded size
    DWORD ecc_sig_buffer_size = 0;
    if (!::CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ECC_SIGNATURE, reinterpret_cast<LPCBYTE>(der_sig.data()),
                               encoded_size, 0 /* dwFlags */,
                               /* PCRYPT_DECODE_PARA */ nullptr,
                               /* pvStructInfo */ nullptr, &ecc_sig_buffer_size))
    {
        mpss::utils::log_warning("CryptDecodeObjectEx failed to get required buffer size with error code {}.",
                                 mpss::utils::to_hex(::GetLastError()));
        return 0;
    }

    // Decode the signature.
    std::unique_ptr<BYTE[]> ecc_sig_buffer = std::make_unique<BYTE[]>(ecc_sig_buffer_size);
    if (!::CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ECC_SIGNATURE, reinterpret_cast<LPCBYTE>(der_sig.data()),
                               encoded_size, 0 /* dwFlags */,
                               /* PCRYPT_DECODE_PARA */ nullptr, ecc_sig_buffer.get(), &ecc_sig_buffer_size))
    {
        mpss::utils::log_warning("CryptDecodeObjectEx failed to decode signature with error code {}.",
                                 mpss::utils::to_hex(::GetLastError()));
        return 0;
    }

    CERT_ECC_SIGNATURE *ecc_sig = reinterpret_cast<CERT_ECC_SIGNATURE *>(ecc_sig_buffer.get());

    const std::size_t key_bytes = mpss::utils::get_key_bytes(algorithm);
    const std::size_t raw_sig_size = 2 * key_bytes;

    // Check that the raw signature has the right size.
    if (ecc_sig->r.cbData > key_bytes || ecc_sig->s.cbData > key_bytes)
    {
        mpss::utils::log_warning("Invalid signature size: r={} bytes, s={} bytes (expected <= {} bytes each).",
                                 ecc_sig->r.cbData, ecc_sig->s.cbData, key_bytes);
        return 0;
    }

    // Set raw_sig to zeros.
    std::fill_n(raw_sig.begin(), raw_sig_size, std::byte{});

    // Copy the raw signature data to the output buffer. Reverse the byte order.
    std::transform(ecc_sig->r.pbData, ecc_sig->r.pbData + ecc_sig->r.cbData, raw_sig.rend() - key_bytes,
                   [](auto in) { return static_cast<std::byte>(in); });
    std::transform(ecc_sig->s.pbData, ecc_sig->s.pbData + ecc_sig->s.cbData, raw_sig.rend() - raw_sig_size,
                   [](auto in) { return static_cast<std::byte>(in); });

    return raw_sig_size;
}

} // namespace mpss::impl::os::utils
