// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

namespace mpss::impl::os
{

/**
 * @brief Base class for Apple key pair implementations.
 *
 * This class provides common functionality for key pair implementations that use Apple APIs for storage and
 * operations. It implements the mpss::KeyPair interface and defines abstract methods for key deletion, signing,
 * verification, and public key extraction that must be implemented by derived classes.
 */
class AppleKeyPairBase : public mpss::KeyPair
{
  public:
    ~AppleKeyPairBase() override = default;

    bool delete_key() override;

    [[nodiscard]]
    std::size_t sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t extract_key(std::span<std::byte> public_key) const override;

    void release_key() override;

  protected:
    AppleKeyPairBase(std::string_view name, Algorithm algorithm, bool hardware_backed, const char *storage_description);

    [[nodiscard]]
    std::string name() const
    {
        return name_;
    }

    virtual bool do_delete_key() = 0;

    [[nodiscard]]
    virtual std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const = 0;

    [[nodiscard]]
    virtual bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const = 0;

    [[nodiscard]]
    virtual std::size_t do_extract_key(std::span<std::byte> public_key) const = 0;

    virtual void do_release_key() = 0;

  private:
    std::string name_;
};

} // namespace mpss::impl::os
