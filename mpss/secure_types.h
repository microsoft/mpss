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
 *
 * Inherits from std::basic_string with CleansingAllocator, which wipes heap-allocated
 * buffers via OPENSSL_cleanse on deallocation. Additionally, the destructor and move/copy
 * operations wipe the string's buffer to cover the Small String Optimization (SSO) case,
 * where short strings are stored inline and never pass through the allocator. This is
 * critical for PIN-length strings (6-8 characters), which are always SSO on major
 * implementations.
 */
class SecureString : public std::basic_string<char, std::char_traits<char>, CleansingAllocator<char>>
{
    using Base = std::basic_string<char, std::char_traits<char>, CleansingAllocator<char>>;

  public:
    using Base::Base;
    using Base::operator=;

    SecureString() = default;

    ~SecureString()
    {
        cleanse();
    }

    SecureString(const SecureString &) = default;

    SecureString(SecureString &&other) noexcept : Base{static_cast<Base &&>(other)}
    {
        other.cleanse();
    }

    SecureString &operator=(const SecureString &other)
    {
        if (this != &other)
        {
            cleanse();
            Base::operator=(other);
        }
        return *this;
    }

    SecureString &operator=(SecureString &&other) noexcept
    {
        if (this != &other)
        {
            cleanse();
            Base::operator=(static_cast<Base &&>(other));
            other.cleanse();
        }
        return *this;
    }

  private:
    /**
     * @brief Cleanse the string's buffer using OPENSSL_cleanse.
     *
     * Wipes capacity() bytes (not just size()) to cover remnant data left by moves,
     * shrinks, or partial overwrites within the SSO buffer.
     */
    void cleanse() noexcept
    {
        if (0 < capacity())
        {
            ::OPENSSL_cleanse(data(), capacity());
        }
    }
};

} // namespace mpss

#endif // MPSS_BACKEND_YUBIKEY
