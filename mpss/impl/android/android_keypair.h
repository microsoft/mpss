// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <cstdint>

namespace mpss::impl::os
{

class AndroidKeyPair : public mpss::KeyPair
{
  public:
    AndroidKeyPair(mpss::Algorithm algorithm, std::string_view name, bool hardware_backed,
                   const char *storage_description, std::uint64_t generation)
        : mpss::KeyPair{algorithm, hardware_backed, storage_description}, key_name_{name}, generation_{generation}
    {
    }

    ~AndroidKeyPair() override
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
    bool close_key();

    std::string key_name_;

    // The cache entry this handle took its hold on, handed back when closing so that a name
    // deleted and created again while this handle was alive cannot have this release charged
    // against the key that now holds the name.
    std::uint64_t generation_;
};

} // namespace mpss::impl::os
