// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

#include <windows.h>
#include <ncrypt.h>


namespace mpss {
    namespace impl {
        class WindowsKeyPair : public mpss::KeyPair {
        public:
            WindowsKeyPair(std::string_view name, mpss::SignatureAlgorithm algorithm, NCRYPT_KEY_HANDLE handle)
                : mpss::KeyPair(name, algorithm), key_handle_(handle)
            {}

            virtual ~WindowsKeyPair()
            {
                win_release();
            }

            virtual bool delete_key() override;

            virtual std::optional<std::vector<std::byte>> sign(gsl::span<std::byte> hash) const override;

            virtual bool verify(gsl::span<std::byte> hash, gsl::span<std::byte> signature) const override;

            virtual bool get_verification_key(std::vector<std::byte>& vk_out) const override;

            virtual void release_key() override;

        private:
            NCRYPT_KEY_HANDLE key_handle_ = 0;

            void win_release();

            void clear_handle();
        };
    }
}
