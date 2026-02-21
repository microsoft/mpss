// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/config.h"

#ifdef MPSS_BACKEND_YUBIKEY

#include <cstddef>
#include <openssl/crypto.h>
#include <string>
#include <vector>

namespace mpss
{

/**
 * @brief Allocator that securely wipes memory on deallocation using OPENSSL_cleanse.
 * @tparam T The allocated element type.
 */
template <typename T> struct CleansingAllocator
{
    using value_type = T;

    CleansingAllocator() = default;
    template <typename U> constexpr CleansingAllocator(const CleansingAllocator<U> &) noexcept
    {
    }

    template <typename U> bool operator==(const CleansingAllocator<U> &) const noexcept
    {
        return true;
    }

    T *allocate(std::size_t n)
    {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T *p, std::size_t n) noexcept
    {
        if (nullptr != p)
        {
            ::OPENSSL_cleanse(p, n * sizeof(T));
            std::allocator<T>{}.deallocate(p, n);
        }
    }
};

/**
 * @brief A byte vector that securely wipes its memory on deallocation.
 */
using SecureByteVector = std::vector<std::byte, CleansingAllocator<std::byte>>;

/**
 * @brief A string type that securely wipes its memory on deallocation.
 */
using SecureString = std::basic_string<char, std::char_traits<char>, CleansingAllocator<char>>;

} // namespace mpss

#endif // MPSS_BACKEND_YUBIKEY
