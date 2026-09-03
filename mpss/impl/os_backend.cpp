// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/os_backend.h"

namespace mpss::impl
{

namespace os
{

// Forward declarations for platform-specific implementations.
// These are implemented in each platform's mpss_impl.cpp.
[[nodiscard]]
std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy);
[[nodiscard]]
std::unique_ptr<KeyPair> open_key(std::string_view name);
[[nodiscard]]
bool delete_key(std::string_view name);
[[nodiscard]]
bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig);

} // namespace os

std::unique_ptr<KeyPair> OSBackend::create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy) const
{
    return os::create_key(name, algorithm, policy);
}

std::unique_ptr<KeyPair> OSBackend::open_key(std::string_view name) const
{
    return os::open_key(name);
}

bool OSBackend::delete_key(std::string_view name) const
{
    return os::delete_key(name);
}

bool OSBackend::verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                       std::span<const std::byte> sig) const
{
    return os::verify(hash, public_key, algorithm, sig);
}

} // namespace mpss::impl
