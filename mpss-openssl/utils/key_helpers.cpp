// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/utils/utils.h"
#include <mpss/mpss.h>
#include <openssl/params.h>
#include <string_view>

namespace mpss_openssl::utils
{

using namespace mpss;

bool get_utf8_parameter(const OSSL_PARAM *param, std::string &value)
{
    if (nullptr == param || OSSL_PARAM_UTF8_STRING != param->data_type || nullptr == param->data ||
        256 < param->data_size)
    {
        return false;
    }

    // Accept an optional terminator, but reject embedded NULs that would change the selected identifier.
    std::string_view text{static_cast<const char *>(param->data), param->data_size};
    if (!text.empty() && '\0' == text.back())
    {
        text.remove_suffix(1);
    }

    if (std::string_view::npos != text.find('\0'))
    {
        return false;
    }

    value.assign(text);
    return true;
}

bool delete_key(std::string_view name)
{
    return KeyPair::Delete(name);
}

bool delete_key(std::string_view name, std::string_view backend_name)
{
    return KeyPair::Delete(name, backend_name);
}

} // namespace mpss_openssl::utils
