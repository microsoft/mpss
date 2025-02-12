// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "mpss/mpss.h"

namespace mpss
{
    namespace impl
    {
        std::unique_ptr<KeyPairHandle> create_key(std::string_view name, SignatureAlgorithm algorithm);

        std::unique_ptr<KeyPairHandle> open_key(std::string_view name);

        int delete_key(const KeyPairHandle& handle);

        std::string sign(const KeyPairHandle& handle, std::string_view data);

        int verify(const KeyPairHandle& handle, std::string_view data, std::string_view signature);

        int get_key(const KeyPairHandle& handle, std::string& vk_out);

        bool is_safe_storage_supported(SignatureAlgorithm algorithm);

        void release_key(const KeyPairHandle& handle);

        std::string get_error();
    }
}
