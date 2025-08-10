// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include "mpss/mpss.h"
#include <memory>
#include <string_view>

namespace mpss {
    namespace impl {
        [[nodiscard]] MPSS_DECOR std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm);

        [[nodiscard]] MPSS_DECOR std::unique_ptr<KeyPair> open_key(std::string_view name);

        [[nodiscard]] MPSS_DECOR bool verify(
            gsl::span<const std::byte> hash,
            gsl::span<const std::byte> public_key,
            Algorithm algorithm,
            gsl::span<const std::byte> sig);

    } // namespace impl
} // namespace mpss
