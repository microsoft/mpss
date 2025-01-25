// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/implementations/mpss_impl.h"

#include <iostream>
#include <stdexcept>
#include <utility>

namespace mpss {
    bool create_key(std::string_view name, SignatureAlgorithm algorithm) {
        int result = impl::create_key(name, algorithm);
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

    std::optional<std::string> sign(std::string_view name, std::string_view hash, SignatureAlgorithm algorithm) {
        std::string signature = impl::sign(name, std::move(hash), algorithm);
        if (signature.size() == 0) {
            return std::nullopt;
        }
        return signature;
    }

    bool verify(std::string_view name, std::string_view hash, std::string_view signature, SignatureAlgorithm algorithm) {
        int result = impl::verify(name, std::move(hash), std::move(signature), algorithm);
        if (result != 0) {
            return false;
        }
        return true;
    }

    bool get_key(std::string_view name, SignatureAlgorithm algorithm, std::string& vk_out) {
        int result = impl::get_key(name, algorithm, vk_out);
        if (result != 0) {
            return false;
        }
        return true;
    }

	bool is_safe_storage_supported(SignatureAlgorithm algorithm) {
		return impl::is_safe_storage_supported(algorithm);
	}

    std::string get_error() {
        return impl::get_error();
    }
} // namespace mpss
