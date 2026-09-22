// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/backend_registry.h"

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

    [[nodiscard]]
    const char *name() const override
    {
        return "os";
    }

    [[nodiscard]]
    std::unique_ptr<KeyPair> create_key(const KeyLocation &location, Algorithm algorithm,
                                        KeyPolicy policy) const override;

    [[nodiscard]]
    std::unique_ptr<KeyPair> open_key(const KeyLocation &location,
                                      std::span<const std::byte> expected_public_key = {}) const override;

    [[nodiscard]]
    bool delete_key(const KeyLocation &location) const override;

    [[nodiscard]]
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                std::span<const std::byte> sig) const override;
};

} // namespace mpss::impl
