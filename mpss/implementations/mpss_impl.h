// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <gsl/gsl>

#include "mpss/mpss.h"

namespace mpss
{
    namespace impl
    {
        std::unique_ptr<KeyPair> create_key(std::string_view name, SignatureAlgorithm algorithm);

        std::unique_ptr<KeyPair> open_key(std::string_view name);

        int delete_key(KeyPair* handle);

        std::vector<std::byte> sign(const KeyPair* handle, gsl::span<std::byte> hash);

        int verify(const KeyPair* handle, gsl::span<std::byte> hash, gsl::span<std::byte> signature);

        int get_key(const KeyPair* handle, std::vector<std::byte>& vk_out);

        bool is_safe_storage_supported(SignatureAlgorithm algorithm);

        void release_key(KeyPair* handle);

        std::string get_error();
    }
}
