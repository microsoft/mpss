// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/implementations/mpss_impl.h"

#include <iostream>
#include <stdexcept>
#include <utility>

namespace mpss {
    bool create_key(std::string_view name) {
        int result = impl::create_key(name);
        if (result != 0) {
            return false;
        }
        return true;
    }

    bool delete_key(std::string_view name) {
        int result = impl::delete_key(name);
        if (result != 0) {
            return false;
        }
        return true;
    }

    std::optional<std::string> sign(std::string_view name, std::string data) {
        std::string signature = impl::sign(name, std::move(data));
        if (signature.size() == 0) {
            return std::nullopt;
        }
        return signature;
    }

    bool verify(std::string_view name, std::string data, std::string signature) {
        int result = impl::verify(name, std::move(data), std::move(signature));
        if (result != 0) {
            return false;
        }
        return true;
    }

    bool get_key(std::string_view name, std::string& vk_out, std::string& sk_out) {
        int result = impl::get_key(name, vk_out, sk_out);
        if (result != 0) {
            return false;
        }
        return true;
    }

    std::string get_error() {
        return impl::get_error();
    }
} // namespace mpss
