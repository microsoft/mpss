// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"

namespace mpss
{
    namespace impl
    {
        std::unique_ptr<KeyPair> create_key(std::string_view name, SignatureAlgorithm algorithm)
        {
            return {};
        }

        std::unique_ptr<KeyPair> open_key(std::string_view name)
        {
            return {};
        }

        bool is_safe_storage_supported(SignatureAlgorithm algorithm)
        {
            return false;
        }

        std::string get_error()
        {
            return {};
        }
    }
}
