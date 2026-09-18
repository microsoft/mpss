// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

namespace mpss::impl::os
{

class AndroidKeyPair : public mpss::KeyPair
{
  public:
    AndroidKeyPair(mpss::Algorithm algorithm, std::string_view name, bool hardware_backed,
                   const char *storage_description)
        : mpss::KeyPair{algorithm, hardware_backed, storage_description}, key_name_{name}
    {
    }

    ~AndroidKeyPair() override
    {
        try
        {
            release_key();
        }
        // NOLINTNEXTLINE(bugprone-empty-catch) - a destructor must not propagate exceptions.
        catch (...)
        {
        }
    }

  protected:
    void do_release_key() override;

    bool do_delete_key() override;

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;

  private:
    void close_key();

    std::string key_name_;
};

} // namespace mpss::impl::os
