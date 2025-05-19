// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include "mpss/implementations/windows/win_utils.h"
#include <Windows.h>
#include <ncrypt.h>

namespace {
    // Instantiating the crypto_params for each algorithm.
    constexpr mpss::impl::ECDSA_P256 ecdsa_p256;
    constexpr mpss::impl::ECDSA_P384 ecdsa_p384;
    constexpr mpss::impl::ECDSA_P521 ecdsa_p521;
} // namespace

namespace mpss::impl::utils {
    crypto_params const *const get_crypto_params(Algorithm algorithm) noexcept
    {
        switch (algorithm) {
        case mpss::Algorithm::ecdsa_secp256r1_sha256:
            return &ecdsa_p256;
        case mpss::Algorithm::ecdsa_secp384r1_sha384:
            return &ecdsa_p384;
        case mpss::Algorithm::ecdsa_secp521r1_sha512:
            return &ecdsa_p521;
        default:
            return nullptr;
        }
    }

    std::size_t decode_raw_signature(
        gsl::span<const std::byte> der_sig,
        Algorithm algorithm,
        gsl::span<std::byte> raw_sig) noexcept
    {
        // Check for obvious problems.
        if (der_sig.empty()) {
            mpss::utils::set_error("Nothing to decode.");
            return 0;
        }
        // Get the algorithm info.
        AlgorithmInfo info = get_algorithm_info(algorithm);
        std::size_t field_size = ((info.key_bits + 7) / 8);
        std::size_t raw_sig_size = field_size * 2;

        // if raw_sig is empty we only want to know the required size
        if (raw_sig.empty()) {
            // Raw signature is two coordinates
            return raw_sig_size;
        }

        // Decode signature
        DWORD encoded_size = mpss::utils::narrow_or_error<DWORD>(der_sig.size());
        if (encoded_size == 0) {
            return 0;
        }

        // Get required decoded size
        DWORD ecc_sig_buffer_size = 0;
        if (!::CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                X509_ECC_SIGNATURE,
                reinterpret_cast<LPCBYTE>(der_sig.data()),
                encoded_size,
                /* dwFlags */ 0,
                /* PCRYPT_DECODE_PARA */ nullptr,
                /* pvStructInfo */ nullptr,
                &ecc_sig_buffer_size)) {
            std::stringstream ss;
            ss << "CryptDecodeObjectEx failed with error code "
               << mpss::utils::to_hex(::GetLastError());
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
                reinterpret_cast<LPCBYTE>(der_sig.data()),
                encoded_size,
                /* dwFlags */ 0,
                /* PCRYPT_DECODE_PARA */ nullptr,
                ecc_sig_buffer.get(),
                &ecc_sig_buffer_size)) {
            std::stringstream ss;
            ss << "CryptDecodeObjectEx failed with error code "
               << mpss::utils::to_hex(::GetLastError());
            mpss::utils::set_error(ss.str());
            return false;
        }

        CERT_ECC_SIGNATURE *ecc_sig = reinterpret_cast<CERT_ECC_SIGNATURE *>(ecc_sig_buffer.get());

        // Copy raw signature
        if (raw_sig.size() < raw_sig_size) {
            std::stringstream ss;
            ss << "Raw signature buffer is too small. Expected " << raw_sig_size << " bytes, got "
               << raw_sig.size() << " bytes.";
            mpss::utils::set_error(ss.str());
            return 0;
        }

        // Copy the raw signature data to the output buffer.
        ::SecureZeroMemory(raw_sig.data(), raw_sig.size());

        std::transform(
            ecc_sig->r.pbData, ecc_sig->r.pbData + ecc_sig->r.cbData, raw_sig.begin(), [](auto in) {
                return static_cast<std::byte>(in);
            });
        std::transform(
            ecc_sig->s.pbData,
            ecc_sig->s.pbData + ecc_sig->s.cbData,
            raw_sig.begin() + field_size,
            [](auto in) { return static_cast<std::byte>(in); });

        return raw_sig_size;
    }
} // namespace mpss::impl::utils
