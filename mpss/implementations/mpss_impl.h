// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "mpss/mpss.h"

namespace mpss
{
    namespace impl
    {
        int create_key(std::string_view name, SignatureAlgorithm algorithm);

        int delete_key(std::string_view name);

		std::string sign(std::string_view name, std::string_view data, SignatureAlgorithm algorithm);

        int verify(std::string_view name, std::string_view data, std::string_view signature, SignatureAlgorithm algorithm);

        int get_key(std::string_view name, SignatureAlgorithm algorithm, std::string& vk_out);

		bool is_safe_storage_supported(SignatureAlgorithm algorithm);

		std::string get_error();
    }
}
