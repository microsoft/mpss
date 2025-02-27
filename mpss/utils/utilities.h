// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"

#include <string>
#include <random>

#include <gsl/gsl>

namespace mpss::utils {
    // Convert a long to a hex string
    std::string to_hex(long value);

    // Get the last error string that occurred
    std::string get_error();

    // Set the last error string that occurred
    void set_error(std::string error);

    // Create a random string of characters.
    std::string random_string(std::size_t length);
}
