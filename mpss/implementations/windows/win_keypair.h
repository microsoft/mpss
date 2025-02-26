// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

#include <Windows.h>
#include <ncrypt.h>

namespace mpss::impl {
    class WindowsKeyPair : public mpss::KeyPair {
    public:
        WindowsKeyPair(std::string_view name, mpss::Algorithm algorithm, NCRYPT_KEY_HANDLE handle)
            : mpss::KeyPair(name, algorithm), key_handle_(handle)
        {}

        ~WindowsKeyPair() override
        {
            win_release();
        }

        bool delete_key() override;

        std::size_t sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const override;

        bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const override;

        std::size_t extract_key(gsl::span<std::byte> public_key) const override;

        void release_key() override;

    private:
        NCRYPT_KEY_HANDLE key_handle_ = 0;

        void win_release();

        void clear_handle();
    };
}
