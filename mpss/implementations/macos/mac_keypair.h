// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

namespace mpss {
    namespace impl {
        class MacKeyPair : public mpss::KeyPair {
        public:
            virtual bool delete_key() override;

            virtual std::optional<std::vector<std::byte>> sign(gsl::span<std::byte> hash) const override;

            virtual bool verify(gsl::span<std::byte> hash, gsl::span<std::byte> signature) const override;

            virtual bool get_verification_key(std::vector<std::byte>& vk_out) const override;

            virtual void release_key() override;
        };
    }
}
