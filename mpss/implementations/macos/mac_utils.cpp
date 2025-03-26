// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mac_utils.h"
#include "mac_se_wrapper.h"

namespace mpss::impl::utils
{
    std::string MPSS_SE_GetLastError()
    {
        std::size_t errorSize = ::MPSS_SE_GetLastError(nullptr, 0);
        std::string error(errorSize, '\0');
        ::MPSS_SE_GetLastError(error.data(), errorSize);
        return error;
    }
}
