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
        std::unique_ptr<KeyPair> create_key(std::string_view name, SignatureAlgorithm algorithm);

        std::unique_ptr<KeyPair> open_key(std::string_view name);

        bool is_safe_storage_supported(SignatureAlgorithm algorithm);

        std::string get_error();
    }
}
