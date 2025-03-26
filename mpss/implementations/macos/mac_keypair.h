// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

namespace mpss
{
    namespace impl
    {
        class MacKeyPair : public mpss::KeyPair
        {
        public:
            MacKeyPair(std::string_view name, Algorithm algorithm, bool secure_enclave = false);
            virtual ~MacKeyPair();

            bool delete_key() override;

            std::size_t sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const override;

            bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const override;

            std::size_t extract_key(gsl::span<std::byte> public_key) const override;

            void release_key() override;

        private:
            std::string name_;
            bool secure_enclave_ = false;
        };
    }
}
