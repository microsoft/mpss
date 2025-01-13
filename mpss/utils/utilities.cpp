// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace {
    thread_local std::string _last_error;
}

namespace mpss {
    namespace utils {
        // Convert a long to a hex string
        std::string to_hex(long value)
        {
            std::stringstream ss;
            ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
            return ss.str();
        }

        std::string get_error()
        {
            return _last_error;
        }

        void set_error(std::string error)
        {
            _last_error = std::move(error);
        }
    }
}
