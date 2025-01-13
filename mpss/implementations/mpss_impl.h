// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace mpss
{
    namespace impl
    {
        int create_key(std::string_view name);

        int delete_key(std::string_view name);

		std::string sign(std::string_view name, std::string data);

        int verify(std::string_view name, std::string data, std::string signature);

        int get_key(std::string_view name, std::string& vk_out, std::string& sk_out);

		std::string get_error();
    }
}
