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
     */
    YubiKeyKeyPair(std::string_view name, Algorithm algorithm, std::uint8_t slot);

    ~YubiKeyKeyPair() override = default;

    bool delete_key() override;

    std::size_t sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    bool verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    std::size_t extract_key(std::span<std::byte> public_key) const override;

    void release_key() override;

  private:
    std::string name_;
    std::uint8_t slot_;
};

} // namespace mpss::impl::yubikey
