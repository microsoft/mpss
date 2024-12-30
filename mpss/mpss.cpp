// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include <iostream>

// Implementation of the MPSS API.
#include "implementations/mpss_impl.h"

// Verify that we are compiling for a supported platform.
#if defined(MPSS_PLATFORM_WINDOWS)
#elif defined(MPSS_PLATFORM_LINUX)
#elif defined(MPSS_PLATFORM_MACOS)
#elif defined(MPSS_PLATFORM_IOS)
#elif defined(MPSS_PLATFORM_ANDROID)
#else
#error "Unsupported platform"
#endif

namespace mpss {
    bool create_key(const std::string& name) {
        int result = mpss::implementation::create_key(name);
        if (result != 0) {
            return false;
        }

        return true;
    }

    bool delete_key(const std::string& name) {
        int result = mpss::implementation::delete_key(name);
        if (result != 0) {
            return false;
        }

        return true;
    }

    std::optional<std::string> sign(const std::string& name, const std::string& data) {
		std::string signature = mpss::implementation::sign(name, data);
        if (signature.size() == 0) {
			return std::nullopt;
        }

		return signature;
    }

    bool verify(const std::string& name, const std::string& data, const std::string& signature) {
		int result = mpss::implementation::verify(name, data, signature);
		if (result != 0) {
			return false;
		}
		return true;
    }

    bool set_key(const std::string& name, const std::string& vk, const std::string& sk) {
        throw std::runtime_error("Not implemented");
    }

    bool get_key(const std::string& name, std::string& vk_out, std::string& sk_out) {
        throw std::runtime_error("Not implemented");
    }

	const std::string& get_error() {
        return mpss::implementation::get_error();
	}
} // namespace mpss
