// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>

namespace mpss
{
    namespace implementation
    {
        int create_key(const std::string& name);

        int delete_key(const std::string& name);

		std::string sign(const std::string& name, const std::string& data);

		int verify(const std::string& name, const std::string& data, const std::string& signature);

        int get_key(const std::string& name, std::string& vk_out, std::string& sk_out);

		const std::string& get_error();
    }
}
