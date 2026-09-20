// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <Windows.h>
#include <ncrypt.h>

namespace mpss::impl::os
{

class WindowsKeyPair : public mpss::KeyPair
{
  public:
    WindowsKeyPair(mpss::Algorithm algorithm, NCRYPT_KEY_HANDLE handle, bool hardware_backed,
                   const char *storage_description)
        : mpss::KeyPair(algorithm, hardware_backed, storage_description), key_handle_(handle)
    {
    }

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
    NCRYPT_KEY_HANDLE key_handle_ = 0;

    SECURITY_STATUS win_release() noexcept;

    void clear_handle() noexcept;
};

} // namespace mpss::impl::os
