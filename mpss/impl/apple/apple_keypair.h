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

    void release_key() override;

  protected:
    AppleKeyPairBase(std::string_view name, Algorithm algorithm, bool hardware_backed, const char *storage_description);

    [[nodiscard]]
    std::string name() const
    {
        return name_;
    }

    virtual void do_release_key() = 0;

  private:
    std::string name_;

    bool released_{false};
};

} // namespace mpss::impl::os
