// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include <iostream>

namespace mpss {
    bool create_key(const std::string& name) {
        throw std::runtime_error("Not implemented");
    }

    bool delete_key(const std::string& name) {
        throw std::runtime_error("Not implemented");
    }

    std::optional<std::string> sign(const std::string& name, const std::string& data) {
        throw std::runtime_error("Not implemented");
    }

    bool verify(const std::string& name, const std::string& data) {
        throw std::runtime_error("Not implemented");
    }

    bool set_key(const std::string& name, const std::string& vk, const std::string& sk) {
        throw std::runtime_error("Not implemented");
    }

    bool get_key(const std::string& name, std::string& vk_out, std::string& sk_out) {
        throw std::runtime_error("Not implemented");
    }
} // namespace mpss
