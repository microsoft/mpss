// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/utilities.h"

#include <iostream>
#include <stdexcept>
#include <utility>


namespace mpss {
    std::unique_ptr<KeyPairHandle> create_key(std::string_view name, SignatureAlgorithm algorithm) {
        return impl::create_key(name, algorithm);
    }

    std::unique_ptr<KeyPairHandle> open_key(std::string_view name)
    {
        return impl::open_key(name);
    }

    bool delete_key(const KeyPairHandlePtr handle) {
        utils::throw_if_null(handle, "handle");

        int result = impl::delete_key(handle);
        if (result != 0) {
            return false;
        }
        return true;
    }

    std::optional<std::string> sign(const KeyPairHandlePtr handle, std::string_view hash) {
        utils::throw_if_null(handle, "handle");

        std::string signature = impl::sign(handle, std::move(hash));
        if (signature.size() == 0) {
            return std::nullopt;
        }
        return signature;
    }

    bool verify(const KeyPairHandlePtr handle, std::string_view hash, std::string_view signature) {
        utils::throw_if_null(handle, "handle");

        int result = impl::verify(handle, std::move(hash), std::move(signature));
        if (result != 0) {
            return false;
        }
        return true;
    }

    bool get_key(const KeyPairHandlePtr handle, std::string& vk_out) {
        utils::throw_if_null(handle, "handle");

        int result = impl::get_key(handle, vk_out);
        if (result != 0) {
            return false;
        }
        return true;
    }

    bool is_safe_storage_supported(SignatureAlgorithm algorithm) {
        return impl::is_safe_storage_supported(algorithm);
    }

    void release_key(const KeyPairHandlePtr handle)
    {
        utils::throw_if_null(handle, "handle");
        impl::release_key(handle);
    }

    std::string get_error() {
        return impl::get_error();
    }

    KeyPairHandle::KeyPairHandle(std::string_view name, SignatureAlgorithm algorithm)
        : name_(std::move(name)), algorithm_(algorithm) {
        switch (algorithm) {
        case SignatureAlgorithm::ECDSA_P256_SHA256:
            hash_size_ = 32;
            break;
        case SignatureAlgorithm::ECDSA_P384_SHA384:
            hash_size_ = 48;
            break;
        case SignatureAlgorithm::ECDSA_P521_SHA512:
            hash_size_ = 64;
            break;
        default:
            throw std::invalid_argument("Unsupported algorithm");
        }
    }

} // namespace mpss
