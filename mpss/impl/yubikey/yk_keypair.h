// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace mpss::impl::yubikey
{

class YubiKeyPIV;

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
     * @param public_key The public key the slot held when this handle opened it, in ANSI X9.63
     * format. A slot can be emptied and filled again under the same name, and a serial and slot
     * alone would address the replacement, so the key itself is what this handle is bound to.
     */
    YubiKeyKeyPair(std::string_view name, Algorithm algorithm, std::uint8_t slot, std::uint32_t serial,
                   std::span<const std::byte> public_key);

    ~YubiKeyKeyPair() override
    {
        release_from_destructor();
    }

  protected:
    bool do_release_key() override;

    bool do_delete_key() override;

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;

  private:
    // Reads what the slot holds now and reports whether it is still the key this handle opened.
    [[nodiscard]]
    bool slot_still_holds_opened_key(YubiKeyPIV &piv) const;

    // Whether bytes read from the slot are the key this handle opened.
    [[nodiscard]]
    bool is_opened_key(std::span<const std::byte> slot_key) const;

    std::string name_;
    std::uint8_t slot_{0};
    std::uint32_t serial_{0};
    std::vector<std::byte> public_key_;
};

} // namespace mpss::impl::yubikey
