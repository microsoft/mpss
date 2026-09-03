// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/utils/utils.h"
#include <memory>
#include <mpss/mpss.h>
#include <string_view>

namespace mpss_openssl::utils
{

using namespace mpss;

bool delete_key(std::string_view name)
{
    return KeyPair::Delete(name);
}

bool delete_key(std::string_view name, std::string_view backend_name)
{
    return KeyPair::Delete(name, backend_name);
}

} // namespace mpss_openssl::utils
