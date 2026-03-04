// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"

namespace
{
thread_local std::string last_error;
}

namespace mpss::utils
{

std::string get_error()
{
    return last_error;
}

void set_error(std::string error) noexcept
{
    last_error = std::move(error);
}

std::size_t get_max_signature_size(Algorithm algorithm)
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        return 0;
    }

    std::size_t max_sig_size = 0;

    switch (algorithm)
    {
    case Algorithm::ecdsa_secp256r1_sha256:
    case Algorithm::ecdsa_secp384r1_sha384:
    case Algorithm::ecdsa_secp521r1_sha512:
        // The maximum signature length is the size of the signature
        // plus the maximum size of the ASN.1 DER encoding.
        //
        // ASN.1 DER encoded ECDSA signatures contain:
        // 1 byte to declare a sequence
        // 2 bytes for the length of the sequence (can be 1 or 2 bytes, depending on the length)
        // 1 byte to declare the first integer
        // 1 byte for the length of the first integer
        // 1 byte to declare the second integer
        // 1 byte for the length of the second integer
        // 1 additional byte if the highest order bit of the first byte of 'r' is 1
        // 1 additional byte if the highest order bit of the first byte of 's' is 1
        //
        // So in total, we have a maximum overhead of 9 bytes to encode two scalars of size key_bits.
        max_sig_size = ((info.key_bits + 7) / 8) * 2 + 9;
        break;
    case Algorithm::unsupported:
        max_sig_size = 0;
        break;
    }

    return max_sig_size;
}

std::size_t get_public_key_size(Algorithm algorithm)
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        return 0;
    }

    std::size_t pk_size = 0;

    switch (algorithm)
    {
    case Algorithm::ecdsa_secp256r1_sha256:
    case Algorithm::ecdsa_secp384r1_sha384:
    case Algorithm::ecdsa_secp521r1_sha512:
        // The public key is ANSI X9.63 encoded, which means it contains:
        // 1 byte for the compression indicator (0x04 for uncompressed)
        // key_bits / 8 bytes for the X coordinate
        // key_bits / 8 bytes for the Y coordinate
        pk_size = ((info.key_bits + 7) / 8) * 2 + 1;
        break;
    case Algorithm::unsupported:
        pk_size = 0;
        break;
    }

    return pk_size;
}

std::size_t get_key_bytes(Algorithm algorithm) noexcept
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    return ((info.key_bits + 7) / 8);
}

std::size_t get_hash_size(Algorithm algorithm) noexcept
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    return ((info.hash_bits + 7) / 8);
}

bool check_exact_hash_size(std::span<const std::byte> hash, Algorithm algorithm) noexcept
{
    const std::size_t expected_hash_size = get_hash_size(algorithm);
    const bool hash_size_ok = (hash.size() == expected_hash_size);
    if (!hash_size_ok)
    {
        mpss::utils::log_warning("Invalid hash length {} bytes for algorithm {} (expected {} bytes).", hash.size(),
                                 get_algorithm_info(algorithm).type_str, expected_hash_size);
    }

    return hash_size_ok;
}

bool check_sufficient_signature_buffer_size(std::span<const std::byte> sig, Algorithm algorithm) noexcept
{
    const std::size_t expected_sig_size = get_max_signature_size(algorithm);
    const bool sig_size_ok = (sig.size() >= expected_sig_size);
    if (!sig_size_ok)
    {
        mpss::utils::log_warning("Signature buffer too small: {} bytes for algorithm {} (expected at least {} bytes).",
                                 sig.size(), get_algorithm_info(algorithm).type_str, expected_sig_size);
    }

    return sig_size_ok;
}

bool check_sufficient_public_key_buffer_size(std::span<const std::byte> public_key, Algorithm algorithm) noexcept
{
    const std::size_t expected_pk_size = get_public_key_size(algorithm);
    const bool pk_size_ok = (public_key.size() >= expected_pk_size);
    if (!pk_size_ok)
    {
        mpss::utils::log_warning("Public key buffer too small: {} bytes for algorithm {} (expected at least {} bytes).",
                                 public_key.size(), get_algorithm_info(algorithm).type_str, expected_pk_size);
    }

    return pk_size_ok;
}

} // namespace mpss::utils
