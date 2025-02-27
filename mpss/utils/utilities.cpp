// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace {
    thread_local std::string last_error;
}

namespace mpss::utils {
    // Convert a long to a hex string
    std::string to_hex(long value)
    {
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
        return ss.str();
    }

    std::string get_error()
    {
        return last_error;
    }

    void set_error(std::string error)
    {
        last_error = std::move(error);
    }

    std::string random_string(std::size_t length)
    {
        static const char chars[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        std::random_device rd;
        std::string result;
        result.reserve(length);
        for (std::size_t i = 0; i < length; i++) {
            result += chars[chars[rd() % (sizeof(chars) - 1)]];
        }
        return result;
    }
}