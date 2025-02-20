// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/utilities.h"

#include <iostream>
#include <stdexcept>
#include <utility>


namespace mpss {
    std::unique_ptr<KeyPair> KeyPair::create(std::string_view name, SignatureAlgorithm algorithm) {
        return impl::create_key(name, algorithm);
    }

    std::unique_ptr<KeyPair> KeyPair::open(std::string_view name)
    {
        return impl::open_key(name);
    }

    bool KeyPair::delete_key() {
        int result = impl::delete_key(this);
        if (result != 0) {
            return false;
        }
        return true;
    }

    std::optional<std::vector<std::byte>> KeyPair::sign(gsl::span<std::byte> hash) const {
        std::vector<std::byte> signature = std::move(impl::sign(this, std::move(hash)));
        if (signature.size() == 0) {
            return std::nullopt;
        }
        return signature;
    }

    bool KeyPair::verify(gsl::span<std::byte> hash, gsl::span<std::byte> signature) const {
        int result = impl::verify(this, std::move(hash), std::move(signature));
        if (result != 0) {
            return false;
        }
        return true;
    }

    bool KeyPair::get_verification_key(std::vector<std::byte>& vk_out) const {
        int result = impl::get_key(this, vk_out);
        if (result != 0) {
            return false;
        }
        return true;
    }

    bool is_safe_storage_supported(SignatureAlgorithm algorithm) {
        return impl::is_safe_storage_supported(algorithm);
    }

    void KeyPair::release_key()
    {
        impl::release_key(this);
    }

    std::string get_error() {
        return impl::get_error();
    }

    KeyPair::KeyPair(std::string_view name, SignatureAlgorithm algorithm)
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
