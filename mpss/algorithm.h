// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <utility>
#include <string_view>

namespace mpss {
    /**
    * @brief The supported signature algorithms.
    */
    enum class Algorithm {
        unsupported,
        ecdsa_secp256r1_sha256,
        ecdsa_secp384r1_sha384,
        ecdsa_secp521r1_sha512
    };

    /**
    * @brief Security info for an algorithm.
    */
    struct AlgorithmInfo {
        const std::size_t security_level;
        const std::size_t hash_bits;
        const std::size_t hash_block_bits;
        char const *const type_str;
    };

    /**
    * @brief A map describing @ref AlgorithmInfo for each supported algorithm.
    */
    constexpr std::array<std::pair<Algorithm, AlgorithmInfo>, 4> algorithm_info = {
        std::make_pair(Algorithm::unsupported, AlgorithmInfo {0, 0, 0, "unsupported" }),
        std::make_pair(Algorithm::ecdsa_secp256r1_sha256, AlgorithmInfo { 128, 256, 32, "ecdsa_secp256r1_sha256" }),
        std::make_pair(Algorithm::ecdsa_secp384r1_sha384, AlgorithmInfo { 192, 384, 64, "ecdsa_secp384r1_sha384" }),
        std::make_pair(Algorithm::ecdsa_secp521r1_sha512, AlgorithmInfo { 256, 512, 64, "ecdsa_secp521r1_sha512" })
    };

    /**
    * @brief Retrieve the @ref AlgorithmInfo for a given @ref Algorithm.
    */
    inline AlgorithmInfo get_algorithm_info(Algorithm algorithm) {
        for (const auto& [alg, info] : algorithm_info) {
            if (alg == algorithm) {
                return info;
            }
        }
        return AlgorithmInfo{ 0, 0, 0 };
    }

    /**
    * @brief Try to find an algorithm corresponding to a given string.
    */
    inline Algorithm algorithm_from_str(std::string_view type_str) {
        for (const auto& [alg, info] : algorithm_info) {
            if (info.type_str == type_str) {
                return alg;
            }
        }
        return Algorithm::unsupported;
    }
}
