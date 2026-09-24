// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/os_backend.h"
#include "mpss/utils/utilities.h"

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

namespace
{
[[nodiscard]]
bool accepts_location(const KeyLocation &location)
{
    if (location.device_id)
    {
        utils::log_and_set_error("The OS backend does not support a device identifier.");
        return false;
    }
    return true;
}
} // namespace

std::unique_ptr<KeyPair> OSBackend::create_key(const KeyLocation &location, Algorithm algorithm, KeyPolicy policy) const
{
    return accepts_location(location) ? os::create_key(location.name, algorithm, policy) : nullptr;
}

std::unique_ptr<KeyPair> OSBackend::open_key(const KeyLocation &location,
                                             std::span<const std::byte> /*expected_public_key*/) const
{
    return accepts_location(location) ? os::open_key(location.name) : nullptr;
}

bool OSBackend::delete_key(const KeyLocation &location) const
{
    return accepts_location(location) && os::delete_key(location.name);
}

bool OSBackend::verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                       std::span<const std::byte> sig) const
{
    return os::verify(hash, public_key, algorithm, sig);
}

} // namespace mpss::impl
