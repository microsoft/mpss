// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace {
    thread_local std::string last_error;
}

namespace mpss::utils {
    // Convert a long to a hex string
    std::string to_hex(long value)
    {
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
        return ss.str();
    }

    std::string get_error() noexcept
    {
        return last_error;
    }

    void set_error(std::string error) noexcept
    {
        last_error = std::move(error);
    }

    std::size_t get_max_signature_length(Algorithm algorithm)
    {
        AlgorithmInfo info = get_algorithm_info(algorithm);
        if (0 == info.key_bits) {
            return 0;
        }

        // The maximum signature length is the size of the signature
        // plus the maximum size of the ASN.1 DER encoding.
        // 
        // ASN.1 DER encoded signatures contain:
        // 1 byte to declare a sequence
        // 2 bytes for the length of the sequence (can be 1 or 2 bytes, depending on the length)
        // 1 byte to declare the first integer
        // 1 byte for the length of the first integer
        // 1 byte to declare the second integer
        // 1 byte for the length of the second integer
        // 1 additional byte if the highest order bit of the first byte of 'r' is 1
        // 1 additional byte if the highest order bit of the first byte of 's' is 1
        // 
        // So in total, we have a maximum overhead of 9 bytes.
        std::size_t max_sig_size = ((info.key_bits + 7) / 8) * 2 + 9;
        return max_sig_size;
    }

    std::size_t get_public_key_size(Algorithm algorithm)
    {
        AlgorithmInfo info = get_algorithm_info(algorithm);
        if (0 == info.key_bits) {
            return 0;
        }

        // The public key size is the size of the X and Y coordinates
        // plus the compression indicator.
        std::size_t pk_size = ((info.key_bits + 7) / 8) * 2 + 1;
        return pk_size;
    }

    std::string random_string(std::size_t length)
    {
        static const char chars[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        std::random_device rd;
        std::string result;
        result.reserve(length);
        for (std::size_t i = 0; i < length; i++) {
            result += chars[chars[rd() % (sizeof(chars) - 1)]];
        }
        return result;
    }

    bool check_hash_length(gsl::span<const std::byte> hash, Algorithm algorithm) noexcept
    {
        AlgorithmInfo info = get_algorithm_info(algorithm);
        if (0 == info.key_bits) {
            return false;
        }
        // The hash length is the size of the hash in bits divided by 8.

        std::size_t hash_length = ((info.hash_bits + 7) / 8);
        return hash.size() == hash_length;
    }
}
