// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/config.h"

#ifdef MPSS_BACKEND_YUBIKEY

#include <cstddef>
#include <openssl/crypto.h>
#include <string>
#include <string_view>
#include <type_traits>
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

    // NOLINTNEXTLINE(*-explicit-constructor) - the Allocator requirements make rebinding implicit.
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
 * Backed by std::basic_string with CleansingAllocator, which wipes heap-allocated buffers via
 * OPENSSL_cleanse on deallocation. Additionally, the destructor and move/copy operations wipe the
 * string's buffer to cover the Small String Optimization (SSO) case, where short strings are stored
 * inline and never pass through the allocator. This is critical for PIN-length strings (6-8
 * characters), which are always SSO on major implementations.
 *
 * Inheritance is private: only a minimal, audited surface is re-exported. Operations that would
 * return a detached std::basic_string (substr, operator+) or slice to the base type are deliberately
 * not exposed, so an accidental attempt to copy secret bytes into a non-cleansing string is a
 * compile error rather than a silent leak.
 */
class SecureString : private std::basic_string<char, std::char_traits<char>, CleansingAllocator<char>>
{
    using Base = std::basic_string<char, std::char_traits<char>, CleansingAllocator<char>>;

  public:
    using Base::Base;

    // Vetted, non-secret-copying surface. Each of these either observes the buffer in place or
    // mutates it in place; none produce a detached basic_string holding secret bytes.
    using Base::c_str;
    using Base::data;
    using Base::empty;
    using Base::push_back;
    using Base::size;
    using Base::operator std::basic_string_view<char, std::char_traits<char>>;

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

    friend bool operator==(const SecureString &lhs, const SecureString &rhs) noexcept
    {
        return std::string_view{lhs} == std::string_view{rhs};
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

// Lock in the leak-prevention invariant: a SecureString must never implicitly slice to its
// non-SSO-cleansing base string. Reverting to public inheritance would break this assertion.
static_assert(
    !std::is_convertible_v<SecureString, std::basic_string<char, std::char_traits<char>, CleansingAllocator<char>>>,
    "SecureString must not be implicitly convertible to its base string type.");

} // namespace mpss

#endif // MPSS_BACKEND_YUBIKEY
