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
        int create_key(std::string_view name, SignatureAlgorithm algorithm, KeyPairHandle* handle);

		int open_key(std::string_view name, KeyPairHandle* handle);

        int delete_key(KeyPairHandle handle);

		std::string sign(KeyPairHandle handle, std::string_view data, SignatureAlgorithm algorithm);

        int verify(KeyPairHandle handle, std::string_view data, std::string_view signature, SignatureAlgorithm algorithm);

        int get_key(KeyPairHandle handle, SignatureAlgorithm algorithm, std::string& vk_out);

		bool is_safe_storage_supported(SignatureAlgorithm algorithm);

		void release_key(KeyPairHandle handle);

		std::string get_error();
    }
}
