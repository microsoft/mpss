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
        std::optional<KeyPairHandle> create_key(std::string_view name, SignatureAlgorithm algorithm);

		std::optional<KeyPairHandle> open_key(std::string_view name);

        int delete_key(const KeyPairHandle& handle);

		std::string sign(const KeyPairHandle& handle, std::string_view data, SignatureAlgorithm algorithm);

        int verify(const KeyPairHandle& handle, std::string_view data, std::string_view signature, SignatureAlgorithm algorithm);

        int get_key(const KeyPairHandle& handle, SignatureAlgorithm algorithm, std::string& vk_out);

		bool is_safe_storage_supported(SignatureAlgorithm algorithm);

		void release_key(const KeyPairHandle& handle);

		std::string get_error();
    }
}
