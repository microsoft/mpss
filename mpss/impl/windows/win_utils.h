// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/windows/crypto_params.h"
#include "mpss/mpss.h"

namespace mpss::impl::os::utils
{

crypto_params const *get_crypto_params(Algorithm algorithm) noexcept;

std::size_t decode_raw_signature(std::span<const std::byte> der_sig, Algorithm algorithm,
                                 std::span<std::byte> raw_sig) noexcept;

} // namespace mpss::impl::os::utils
