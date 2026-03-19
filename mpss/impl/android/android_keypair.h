// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/android/JNIHelper.h"
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
        // Release on destruction.
        close_key();
    }

    bool delete_key() override;

    [[nodiscard]]
    std::size_t sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t extract_key(std::span<std::byte> public_key) const override;

    void release_key() noexcept override;

  private:
    void close_key();
    [[nodiscard]]
    JNIEnv *env() const
    {
        return guard_.Env();
    };

    std::string key_name_;
    JNIEnvGuard guard_;
};

} // namespace mpss::impl::os
