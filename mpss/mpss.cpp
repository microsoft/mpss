// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/utilities.h"

#include <iostream>
#include <stdexcept>
#include <utility>


namespace mpss {
    std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm) {
        return impl::create_key(name, algorithm);
    }

    std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name)
    {
        return impl::open_key(name);
    }

    bool is_safe_storage_supported(Algorithm algorithm) {
        return impl::is_safe_storage_supported(algorithm);
    }

    std::string get_error() {
        return impl::get_error();
    }

    KeyPair::KeyPair(std::string_view name, Algorithm algorithm)
        : name_(name), algorithm_(algorithm) {
        switch (algorithm) {
        case Algorithm::ECDSA_P256_SHA256:
            hash_size_ = 32;
            break;
        case Algorithm::ECDSA_P384_SHA384:
            hash_size_ = 48;
            break;
        case Algorithm::ECDSA_P521_SHA512:
            hash_size_ = 64;
            break;
        default:
            throw std::invalid_argument("Unsupported algorithm");
        }
    }
} // namespace mpss
