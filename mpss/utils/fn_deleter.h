// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

namespace mpss::utils
{

/**
 * @brief Deleter that releases an object with a compile-time known function.
 *
 * @p Fn is a template parameter rather than a stored function pointer, so the deleter is an empty
 * class and a `std::unique_ptr` using it stays the size of a raw pointer.
 */
template <auto Fn> struct fn_deleter
{
    template <typename T> void operator()(T *ptr) const noexcept
    {
        Fn(ptr);
    }
};

} // namespace mpss::utils
