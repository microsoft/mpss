// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <limits>
#include <memory>
#include <mpss/mpss.h>
#include <new>
#include <openssl/crypto.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mpss_openssl::utils {
    template <typename T, typename... Args>
    [[nodiscard]] inline T *mpss_new(Args &&...args)
    {
        T *obj = static_cast<T *>(OPENSSL_zalloc(sizeof(T)));
        if (!obj) {
            throw std::bad_alloc();
        }

        ::new (obj) T(std::forward<Args>(args)...);
        return obj;
    }

    template <bool clear_on_free, typename T>
    void inline mpss_delete(T *obj)
    {
        if (obj) {
            std::destroy_at(obj);

            if constexpr (clear_on_free) {
                OPENSSL_clear_free(obj, sizeof(T));
            } else {
                OPENSSL_free(obj);
            }
        }
    }

    template <typename T>
    struct NeatAllocator {
        using value_type = T;
        using pointer = T *;
        using const_pointer = const T *;
        using void_pointer = void *;
        using const_void_pointer = const void *;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;

        inline NeatAllocator() = default;

        template <typename U>
        inline constexpr NeatAllocator(const NeatAllocator<U> &) noexcept
        {}

        [[nodiscard]] inline pointer allocate(size_type n)
        {
            if (n > max_size()) {
                throw std::bad_array_new_length();
            }

            T *p = static_cast<T *>(OPENSSL_zalloc(n * sizeof(T)));
            if (!p) {
                throw std::bad_alloc();
            }

            return p;
        }

        [[nodiscard]] inline constexpr size_type max_size() const noexcept
        {
            return std::numeric_limits<size_type>::max() / sizeof(T);
        }

        inline void deallocate(T *p, std::size_t n) noexcept
        {
            if (p) {
                OPENSSL_clear_free(p, n * sizeof(T));
            }
        }
    };

    template <typename T, typename U>
    [[nodiscard]] inline bool operator==(
        const NeatAllocator<T> &, const NeatAllocator<U> &) noexcept
    {
        return false;
    }

    template <typename T>
    [[nodiscard]] inline bool operator==(
        const NeatAllocator<T> &, const NeatAllocator<T> &) noexcept
    {
        return true;
    }

    template <typename T, typename U>
    [[nodiscard]] bool operator!=(const NeatAllocator<T> &lhs, const NeatAllocator<U> &rhs) noexcept
    {
        return !operator==(lhs, rhs);
    }

    template <typename T>
    struct CommonAllocator {
        using value_type = T;
        using pointer = T *;
        using const_pointer = const T *;
        using void_pointer = void *;
        using const_void_pointer = const void *;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;

        inline CommonAllocator() = default;

        template <typename U>
        inline constexpr CommonAllocator(const CommonAllocator<U> &) noexcept
        {}

        [[nodiscard]] inline pointer allocate(size_type n)
        {
            if (n > max_size()) {
                throw std::bad_array_new_length();
            }

            T *p = static_cast<T *>(OPENSSL_zalloc(n * sizeof(T)));
            if (!p) {
                throw std::bad_alloc();
            }

            return p;
        }

        [[nodiscard]] inline constexpr size_type max_size() const noexcept
        {
            return std::numeric_limits<size_type>::max() / sizeof(T);
        }

        inline void deallocate(T *p, std::size_t n) noexcept
        {
            if (p) {
                OPENSSL_free(p);
            }
        }
    };

    template <typename T, typename U>
    [[nodiscard]] inline bool operator==(
        const CommonAllocator<T> &, const CommonAllocator<U> &) noexcept
    {
        return false;
    }

    template <typename T>
    [[nodiscard]] inline bool operator==(
        const CommonAllocator<T> &, const CommonAllocator<T> &) noexcept
    {
        return true;
    }

    template <typename T, typename U>
    [[nodiscard]] inline bool operator!=(
        const CommonAllocator<T> &lhs, const CommonAllocator<U> &rhs) noexcept
    {
        return !operator==(lhs, rhs);
    }

    // set the allocator according to the neat bool.
    using neat_byte_vector = std::vector<std::byte, NeatAllocator<std::byte>>;
    using common_byte_vector = std::vector<std::byte, CommonAllocator<std::byte>>;

    using neat_string = std::basic_string<char, std::char_traits<char>, NeatAllocator<char>>;
    using common_string = std::basic_string<char, std::char_traits<char>, CommonAllocator<char>>;
} // namespace mpss_openssl::utils