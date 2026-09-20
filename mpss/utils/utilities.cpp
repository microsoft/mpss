// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"
#include <array>
#include <functional>
#include <mutex>
#include <new>

namespace
{
// Immortal per-thread error string: heap-allocated at most once per thread and never destroyed, so
// it stays valid even when MPSS is called from a host's static/global destructor during process
// exit. A plain thread_local std::string is destroyed strongly-before static-duration objects
// ([basic.start.term]), so a host static destructor that reaches set_error() would write into a
// freed string.
//
// The slot starts null and is filled only when there is an error to record, so reading the last
// error never allocates. That keeps get_error() and has_error() usable on a thread that has never
// touched MPSS, and lets has_error() promise not to allocate.
std::string *&last_error_slot() noexcept
{
    thread_local std::string *error = nullptr;
    return error;
}
} // namespace

namespace mpss::utils
{

std::string get_error()
{
    const std::string *error = last_error_slot();
    return (nullptr == error) ? std::string{} : *error;
}

bool has_error() noexcept
{
    const std::string *error = last_error_slot();
    return (nullptr != error) && !error->empty();
}

void set_error(std::string error) noexcept
{
    std::string *&slot = last_error_slot();
    if (nullptr == slot)
    {
        if (error.empty())
        {
            // Clearing an error on a thread that has never reported one: nothing to store.
            return;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory) - intentional immortal per-thread storage, never freed.
        slot = new (std::nothrow) std::string();
        if (nullptr == slot)
        {
            // Out of memory while reporting an error. Dropping the message is better than
            // terminating, which is what throwing out of this noexcept function would do.
            return;
        }
    }

    *slot = std::move(error);
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
        max_sig_size = (((info.key_bits + 7) / 8) * 2) + 9;
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
        pk_size = (((info.key_bits + 7) / 8) * 2) + 1;
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

bool check_exact_hash_size(std::span<const std::byte> hash, Algorithm algorithm)
{
    const std::size_t expected_hash_size = get_hash_size(algorithm);
    const bool hash_size_ok = (hash.size() == expected_hash_size);
    if (!hash_size_ok)
    {
        mpss::utils::log_and_set_error("Invalid hash length {} bytes for algorithm {} (expected {} bytes).",
                                       hash.size(), get_algorithm_info(algorithm).type_str, expected_hash_size);
    }

    return hash_size_ok;
}

bool check_sufficient_signature_buffer_size(std::span<const std::byte> sig, Algorithm algorithm)
{
    const std::size_t expected_sig_size = get_max_signature_size(algorithm);
    const bool sig_size_ok = (sig.size() >= expected_sig_size);
    if (!sig_size_ok)
    {
        mpss::utils::log_and_set_error(
            "Signature buffer too small: {} bytes for algorithm {} (expected at least {} bytes).", sig.size(),
            get_algorithm_info(algorithm).type_str, expected_sig_size);
    }

    return sig_size_ok;
}

bool check_sufficient_public_key_buffer_size(std::span<const std::byte> public_key, Algorithm algorithm)
{
    const std::size_t expected_pk_size = get_public_key_size(algorithm);
    const bool pk_size_ok = (public_key.size() >= expected_pk_size);
    if (!pk_size_ok)
    {
        mpss::utils::log_and_set_error(
            "Public key buffer too small: {} bytes for algorithm {} (expected at least {} bytes).", public_key.size(),
            get_algorithm_info(algorithm).type_str, expected_pk_size);
    }

    return pk_size_ok;
}

namespace
{
// Depth rather than a flag, so a handler reached from another handler still reads as inside one.
thread_local int interaction_handler_depth = 0;
} // namespace

std::mutex &name_mutex(std::string_view name)
{
    constexpr std::size_t stripe_count = 64;
    using Stripes = std::array<std::mutex, stripe_count>;

    // Immortal singleton state, for the same reason as the backend registry: a lifecycle operation
    // running after this one was destroyed would otherwise lock a destroyed mutex. The one-time
    // allocation is reclaimed by the OS at process exit.
    static Stripes &stripes = []() -> Stripes & {
        auto *fresh = new Stripes{}; // NOLINT(cppcoreguidelines-owning-memory) - intentional immortal singleton.
        return *fresh;
    }();

    return stripes.at(std::hash<std::string_view>{}(name) % stripe_count);
}

bool in_interaction_handler() noexcept
{
    return 0 != interaction_handler_depth;
}

InteractionHandlerScope::InteractionHandlerScope() noexcept
{
    ++interaction_handler_depth;
}

InteractionHandlerScope::~InteractionHandlerScope() noexcept
{
    --interaction_handler_depth;
}

} // namespace mpss::utils
