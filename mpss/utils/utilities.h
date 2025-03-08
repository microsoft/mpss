// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

#include <string>
#include <random>

#include <gsl/narrow>

namespace mpss::utils {
    // Convert a long to a hex string
    std::string to_hex(long value);

    // Get the last error string that occurred
    std::string get_error() noexcept;

    // Set the last error string that occurred
    void set_error(std::string error) noexcept;

    // Create a random string of characters.
    std::string random_string(std::size_t length);

    // Try to narrow input. On failure, set an error and return zero.
    template<typename Out, typename In>
    Out narrow_or_error(In in) {
        Out out;
        try {
            out = gsl::narrow<Out>(in);
        }
        catch (const gsl::narrowing_error& e) {
            // Narrowing failed.
            utils::set_error("Narrowing error.");
            out = Out{ 0 };
        }
        return out;
    }
}
