// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <cstdint>

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

  protected:
    AppleKeyPairBase(std::string_view name, Algorithm algorithm, StorageTier storage_tier, std::uint64_t generation);

    [[nodiscard]]
    std::string name() const
    {
        return name_;
    }

    // The cache entry this handle took its hold on. Handed back when releasing so that a name
    // deleted and created again while this handle was alive cannot have this release charged
    // against the key that now holds the name.
    [[nodiscard]]
    std::uint64_t generation() const noexcept
    {
        return generation_;
    }

  private:
    std::string name_;

    std::uint64_t generation_;
};

} // namespace mpss::impl::os
