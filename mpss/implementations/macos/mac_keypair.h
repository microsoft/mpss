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
            MacKeyPair(std::string_view name, Algorithm algorithm);
            virtual ~MacKeyPair();

            bool delete_key() override;

            std::size_t sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const override;

            bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const override;

            std::size_t extract_key(gsl::span<std::byte> public_key) const override;

            void release_key() override;

        protected:
            MacKeyPair(std::string_view name, Algorithm algorithm, bool hardware_backed, const char* storage_description);
            
            const std::string &name() const
            {
                return name_;
            }

            virtual bool do_delete_key();
            virtual std::size_t do_sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const;
            virtual bool do_verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const;
            virtual std::size_t do_extract_key(gsl::span<std::byte> public_key) const;
            virtual void do_release_key();

        private:
            std::string name_;
        };
    }
}
