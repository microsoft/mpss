// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include "mpss/log.h"
#include <charconv>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mpss::utils
{

/**
 * @brief Convert a long integer to a hexadecimal string.
 * @param value The long integer to convert.
 * @return The hexadecimal string representation of the input value.
 */
inline std::string to_hex(long value)
{
    return std::format("0x{:08x}", static_cast<unsigned long>(value));
}

/**
 * @brief Convert a hexadecimal string to a vector of bytes.
 * @param hex_str The hexadecimal string to convert.
 * @return An optional vector of bytes if the conversion was successful, or std::nullopt if the input string was not
 * a valid hexadecimal string.
 */
template <typename ByteVectorType = std::vector<std::byte>>
std::optional<ByteVectorType> hex_string_to_bytes(std::string_view hex_str)
{
    // Validation: Hex strings must have an even number of characters.
    if (0 != hex_str.size() % 2)
    {
        return std::nullopt;
    }

    ByteVectorType bytes;
    bytes.reserve(hex_str.size() / 2);

    for (std::size_t i = 0; i < hex_str.size(); i += 2)
    {
        std::uint8_t this_byte{};
        auto [ptr, ec] = std::from_chars(hex_str.data() + i, hex_str.data() + i + 2, this_byte, 16);
        if (ec != std::errc{})
        {
            return std::nullopt;
        }

        bytes.push_back(static_cast<std::byte>(this_byte));
    }

    return bytes;
}

/**
 * @brief Return the last error that occurred in the library.
 * @return The last error that occurred in the library.
 */
std::string get_error();

/**
 * @brief Set the last error string that occurred.
 * @param error The error string to set.
 */
void set_error(std::string error) noexcept;

/**
 * @brief Log an error message and set it as the last error.
 * @param msg The error message to log and set.
 */
inline void log_and_set_error(std::string msg)
{
    if (auto logger = mpss::GetLogger())
    {
        logger->error("{}", msg);
    }
    set_error(std::move(msg));
}

/**
 * @brief Log a formatted error message and set it as the last error.
 * @param fmt The format string for the error message.
 * @param args The format arguments for the error message.
 */
template <typename... Args> void log_and_set_error(std::format_string<Args...> fmt, Args &&...args)
{
    log_and_set_error(std::format(fmt, std::forward<Args>(args)...));
}

/**
 * @brief Log a warning message.
 * @param msg The warning message to log.
 */
inline void log_warn(std::string msg)
{
    if (auto logger = mpss::GetLogger())
    {
        logger->warn("{}", msg);
    }
}

/**
 * @brief Log a formatted warning message.
 * @param fmt The format string for the warning message.
 * @param args The format arguments for the warning message.
 */
template <typename... Args> void log_warn(std::format_string<Args...> fmt, Args &&...args)
{
    log_warn(std::format(fmt, std::forward<Args>(args)...));
}

/**
 * @brief Log an info message.
 * @param msg The info message to log.
 */
inline void log_info(std::string msg)
{
    if (auto logger = mpss::GetLogger())
    {
        logger->info("{}", msg);
    }
}

/**
 * @brief Log a formatted info message.
 * @param fmt The format string for the info message.
 * @param args The format arguments for the info message.
 */
template <typename... Args> void log_info(std::format_string<Args...> fmt, Args &&...args)
{
    log_info(std::format(fmt, std::forward<Args>(args)...));
}

/**
 * @brief Log a debug message.
 * @param msg The debug message to log.
 */
inline void log_debug(std::string msg)
{
    if (auto logger = mpss::GetLogger())
    {
        logger->debug("{}", msg);
    }
}

/**
 * @brief Log a formatted debug message.
 * @param fmt The format string for the debug message.
 * @param args The format arguments for the debug message.
 */
template <typename... Args> void log_debug(std::format_string<Args...> fmt, Args &&...args)
{
    log_debug(std::format(fmt, std::forward<Args>(args)...));
}

/**
 * @brief Get maximum signature size for a given algorithm.
 * @param algorithm The algorithm to get the maximum signature size for.
 * @return The maximum signature size.
 * @note We assume that the signature is ASN.1 DER encoded.
 */
std::size_t get_max_signature_size(Algorithm algorithm);

/**
 * @brief Get public key size for a given algorithm.
 * @param algorithm The algorithm to get the public key size for.
 * @return The public key size.
 * @note We assume that the public key is ANSI X9.63 encoded.
 */
std::size_t get_public_key_size(Algorithm algorithm);

/**
 * @brief Try to narrow input. On failure, set an error and return zero.
 * @tparam Out The output type.
 * @tparam In The input type.
 * @param in The input value to narrow.
 * @return The narrowed value or zero on failure.
 */
template <std::integral Out, std::integral In> Out narrow_or_error(In in)
{
    if (!std::in_range<Out>(in))
    {
        log_and_set_error("Narrowing error (in value: {})", in);
        return Out{0};
    }
    return static_cast<Out>(in);
}

/**
 * @brief Get the key size in bytes for a given algorithm.
 * @param algorithm The algorithm to get the key size for.
 * @return The key size in bytes (i.e., the byte length of one curve scalar).
 */
std::size_t get_key_bytes(Algorithm algorithm) noexcept;

/**
 * @brief Get the expected hash size for a given algorithm.
 * @param algorithm The algorithm to get the expected hash size for.
 * @return The expected hash size for the given algorithm.
 */
std::size_t get_hash_size(Algorithm algorithm) noexcept;

/**
 * @brief Check that the given hash buffer has the expected size for the given algorithm.
 * @param hash The hash buffer to check.
 * @param algorithm The algorithm to check the hash buffer size for.
 * @return true if the hash buffer has exactly the expected size for the given algorithm, false otherwise.
 */
bool check_exact_hash_size(std::span<const std::byte> hash, Algorithm algorithm) noexcept;

/**
 * @brief Check that the given signature buffer has at least the expected size for the given algorithm.
 * @param sig The signature buffer to check.
 * @param algorithm The algorithm to check the signature buffer size for.
 * @return true if the signature buffer has at least the expected size for the given algorithm, false
 * otherwise.
 */
bool check_sufficient_signature_buffer_size(std::span<const std::byte> sig, Algorithm algorithm) noexcept;

/**
 * @brief Check that the given public key buffer has at least the expected size for the given algorithm.
 * @param public_key The public key buffer to check.
 * @param algorithm The algorithm to check the public key buffer size for.
 * @return true if the public key buffer has at least the expected size for the given algorithm, false
 * otherwise.
 */
bool check_sufficient_public_key_buffer_size(std::span<const std::byte> public_key, Algorithm algorithm) noexcept;

} // namespace mpss::utils
