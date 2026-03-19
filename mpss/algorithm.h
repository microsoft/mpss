// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include <array>
#include <string_view>
#include <utility>

namespace mpss
{
/**
 * @brief The supported signature algorithms.
 */
enum class MPSS_DECOR Algorithm : int
{
    unsupported = 0,
    ecdsa_secp256r1_sha256 = 1,
    ecdsa_secp384r1_sha384 = 2,
    ecdsa_secp521r1_sha512 = 3
};

/**
 * @brief Security info for an algorithm.
 */
// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members) - immutable data record by design.
struct MPSS_DECOR AlgorithmInfo
{
    const std::size_t key_bits;
    const std::size_t security_bits;
    const std::size_t hash_bits;
    char const *const type_str;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

/**
 * @brief A map describing @ref AlgorithmInfo for each supported algorithm.
 */
constexpr std::array<std::pair<Algorithm, AlgorithmInfo>, 4> algorithm_info = {
    std::make_pair(Algorithm::unsupported,
                   AlgorithmInfo{.key_bits = 0, .security_bits = 0, .hash_bits = 0, .type_str = "unsupported"}),
    std::make_pair(
        Algorithm::ecdsa_secp256r1_sha256,
        AlgorithmInfo{.key_bits = 256, .security_bits = 128, .hash_bits = 256, .type_str = "ecdsa_secp256r1_sha256"}),
    std::make_pair(
        Algorithm::ecdsa_secp384r1_sha384,
        AlgorithmInfo{.key_bits = 384, .security_bits = 192, .hash_bits = 384, .type_str = "ecdsa_secp384r1_sha384"}),
    std::make_pair(
        Algorithm::ecdsa_secp521r1_sha512,
        AlgorithmInfo{.key_bits = 521, .security_bits = 256, .hash_bits = 512, .type_str = "ecdsa_secp521r1_sha512"})};

/**
 * @brief Retrieve the @ref AlgorithmInfo for a given @ref Algorithm.
 */
constexpr AlgorithmInfo get_algorithm_info(Algorithm algorithm)
{
    for (const auto &[alg, info] : algorithm_info)
    {
        if (alg == algorithm)
        {
            return info;
        }
    }
    return algorithm_info[0].second;
}

/**
 * @brief Try to find an algorithm corresponding to a given string.
 */
constexpr Algorithm algorithm_from_str(std::string_view type_str)
{
    for (const auto &[alg, info] : algorithm_info)
    {
        if (info.type_str == type_str)
        {
            return alg;
        }
    }
    return Algorithm::unsupported;
}

} // namespace mpss
