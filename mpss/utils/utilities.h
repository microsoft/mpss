// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>

namespace mpss {
    namespace utils {
        // Convert a long to a hex string
        std::string to_hex(long value);

        // Get the last error string that occurred
        std::string get_error();

        // Set the last error string that occurred
        void set_error(std::string error);
    }
}
