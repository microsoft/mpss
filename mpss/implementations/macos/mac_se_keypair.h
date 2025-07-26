// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mac_keypair.h"

namespace mpss {
    namespace impl {
        class MacSEKeyPair : public MacKeyPair {
        public:
            MacSEKeyPair(std::string_view name, Algorithm algorithm);
            virtual ~MacSEKeyPair();

        protected:
            bool do_delete_key() override;
            std::size_t do_sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const override;
            bool do_verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const override;
            std::size_t do_extract_key(gsl::span<std::byte> public_key) const override;
            void do_release_key() override;
        };
    } // namespace impl
} // namespace mpss
