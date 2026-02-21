// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/implementations/backend_registry.h"

namespace mpss::impl
{

/**
 * @brief Backend implementation that wraps the OS-native implementation.
 *
 * This backend delegates to the platform-specific implementation on
 * Windows, macOS, iOS, and Android.
 */
class OSBackend : public Backend
{
  public:
    OSBackend() = default;

    ~OSBackend() override = default;

    [[nodiscard]] std::string name() const override
    {
        return "os";
    }

    [[nodiscard]] std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm) const override;

    [[nodiscard]] std::unique_ptr<KeyPair> open_key(std::string_view name) const override;

    [[nodiscard]] bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key,
                              Algorithm algorithm, std::span<const std::byte> sig) const override;

    [[nodiscard]] bool is_available() const override;
};

/**
 * @brief Register the OS backend with the registry.
 *
 * This function should be called during initialization to make the
 * OS backend available. It is automatically called by the platform-specific
 * implementation.
 */
void register_os_backend();

} // namespace mpss::impl
