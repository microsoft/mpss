// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/os_backend.h"
#include "mpss/impl/backend_registry.h"

namespace mpss::impl
{

namespace os
{

// Forward declarations for platform-specific implementations.
// These are implemented in each platform's mpss_impl.cpp.
[[nodiscard]] std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm);
[[nodiscard]] std::unique_ptr<KeyPair> open_key(std::string_view name);
[[nodiscard]] bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                          std::span<const std::byte> sig);

} // namespace os

std::unique_ptr<KeyPair> OSBackend::create_key(std::string_view name, Algorithm algorithm, KeyPolicy /*policy*/) const
{
    return os::create_key(name, algorithm);
}

std::unique_ptr<KeyPair> OSBackend::open_key(std::string_view name) const
{
    return os::open_key(name);
}

bool OSBackend::verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                       std::span<const std::byte> sig) const
{
    return os::verify(hash, public_key, algorithm, sig);
}

bool OSBackend::is_available() const
{
#if defined(_WIN32) || defined(__APPLE__) || defined(__ANDROID__)
    return true;
#else
    return false;
#endif
}

void register_os_backend()
{
    auto backend = std::make_shared<OSBackend>();
    register_backend(backend);
}

} // namespace mpss::impl
