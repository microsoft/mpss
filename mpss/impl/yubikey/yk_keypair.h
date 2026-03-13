// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <cstdint>
#include <string>

namespace mpss::impl::yubikey
{

/**
 * @brief KeyPair implementation for YubiKey PIV backend.
 */
class YubiKeyKeyPair : public mpss::KeyPair
{
  public:
    /**
     * @brief Constructs a YubiKeyKeyPair for an existing key on the device.
     * @param name The key name.
     * @param algorithm The signature algorithm.
     * @param slot The PIV slot number where the key is stored.
     * @param serial The serial number of the YubiKey that holds this key.
     */
    YubiKeyKeyPair(std::string_view name, Algorithm algorithm, std::uint8_t slot, std::uint32_t serial);

    ~YubiKeyKeyPair() override = default;

    bool delete_key() override;

    [[nodiscard]]
    std::size_t sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t extract_key(std::span<std::byte> public_key) const override;

    void release_key() override;

  private:
    std::string name_;
    std::uint8_t slot_{0};
    std::uint32_t serial_{0};
};

} // namespace mpss::impl::yubikey
