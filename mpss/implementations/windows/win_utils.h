// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include "mpss/implementations/windows/crypto_params.h"

#include <string>

#include <Windows.h>

namespace mpss::impl::utils {
    crypto_params const* const get_crypto_params(Algorithm algorithm) noexcept;

    void set_error(SECURITY_STATUS status, std::string error) noexcept;
}
