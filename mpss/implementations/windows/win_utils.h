// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include "mpss/implementations/windows/crypto_params.h"

namespace mpss::impl::utils {
    crypto_params const* const get_crypto_params(Algorithm algorithm) noexcept;

    std::size_t decode_raw_signature(
        gsl::span<const std::byte> der_sig,
        Algorithm algorithm,
        gsl::span<std::byte> raw_sig) noexcept;
}
