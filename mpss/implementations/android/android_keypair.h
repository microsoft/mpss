// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/implementations/mpss_impl.h"
#include "mpss/implementations/android/JNIHelper.h"

namespace mpss {
    namespace impl {
        class AndroidKeyPair : public mpss::KeyPair {
        public:
            AndroidKeyPair(
                mpss::Algorithm algorithm, std::string_view name, bool hardware_backed, const char *storage_description)
                : mpss::KeyPair(algorithm, hardware_backed, storage_description), key_name_(name)
            {}

            ~AndroidKeyPair() override
            {
                // Release on destruction
                close_key();
            }

            bool delete_key() override;

            std::size_t sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const override;

            bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const override;

            std::size_t extract_key(gsl::span<std::byte> public_key) const override;

            void release_key() noexcept override;

        private:
            void close_key();
            JNIEnv *env() const
            {
                return guard_.Env();
            };

            std::string key_name_;
            JNIEnvGuard guard_;
        };
    } // namespace impl
} // namespace mpss
