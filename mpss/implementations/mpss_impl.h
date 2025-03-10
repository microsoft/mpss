// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

#include <memory>
#include <string>
#include <string_view>

namespace mpss
{
    namespace impl
    {
        [[nodiscard]] std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm);

        [[nodiscard]] std::unique_ptr<KeyPair> open_key(std::string_view name);
    }
}
