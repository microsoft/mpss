// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <Windows.h>
#include <cstdint>
#include <ncrypt.h>
#include <string>
#include <string_view>

namespace mpss::impl::os
{

class WindowsKeyPair : public mpss::KeyPair
{
  public:
    WindowsKeyPair(std::string_view name, mpss::Algorithm algorithm, NCRYPT_KEY_HANDLE handle,
                   mpss::StorageTier storage_tier, std::uint64_t generation);

    ~WindowsKeyPair() override
    {
        release_from_destructor();
    }

  protected:
    bool do_delete_key() override;

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;

    bool do_release_key() override;

  private:
    std::string name_;

    NCRYPT_KEY_HANDLE key_handle_ = 0;

    // The generation read before this handle's key was opened, handed back on every operation so
    // that a name taken again by a different key is not reached through the key that held it
    // before.
    std::uint64_t generation_ = 0;

    [[nodiscard]]
    bool still_holds_opened_key() const;

    SECURITY_STATUS win_release() noexcept;

    void clear_handle() noexcept;
};

} // namespace mpss::impl::os
