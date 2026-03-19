// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/apple/apple_utils.h"
#include "mpss/impl/apple/apple_se_wrapper.h"

namespace mpss::impl::os::utils
{

std::string MPSS_SE_GetLastError()
{
    const std::size_t errorSize = ::MPSS_SE_GetLastError(nullptr, 0);
    std::string error(errorSize, '\0');
    ::MPSS_SE_GetLastError(error.data(), errorSize);
    return error;
}

} // namespace mpss::impl::os::utils
