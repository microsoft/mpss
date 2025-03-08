// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/utilities.h"

#include <iostream>
#include <stdexcept>

namespace mpss {
    std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm) {
        return impl::create_key(name, algorithm);
    }

    std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name)
    {
        return impl::open_key(name);
    }

    bool is_algorithm_supported(Algorithm algorithm) {
        AlgorithmInfo info = get_algorithm_info(algorithm);
        if (0 == info.key_bits) {
            return false;
        }

        // Sample a random name for a key and try creating it.
        std::string random_key = "MPSS_TEST_KEY_" + mpss::utils::random_string(16) + "_CAN_DELETE";
        std::unique_ptr<KeyPair> key = KeyPair::Create(random_key, algorithm);

        // Could we even create a key?
        bool key_created = (nullptr != key);
        if (!key_created) {
            return false;
        }

        // Create some data and sign.
        std::vector<std::byte> hash(info.hash_bits / 8, static_cast<std::byte>('a'));
        std::size_t sig_size = key->sign_hash(hash, {});
        if (0 == sig_size) {
            bool key_deleted = key->delete_key();
            if (!key_deleted) {
                throw std::runtime_error("Test key deletion failed");
            }
            return false;
        }

        std::vector<std::byte> sig(sig_size);
        std::size_t written = key->sign_hash(hash, sig);
        if (written != sig_size) {
            bool key_deleted = key->delete_key();
            if (!key_deleted) {
                throw std::runtime_error("Test key deletion failed");
            }
            return false;
        }

        bool key_deleted = key->delete_key();

        // Did everything work out?
        return key_deleted;
    }

    std::string get_error() noexcept {
        return impl::get_error();
    }

    KeyPair::KeyPair(std::string_view name, Algorithm algorithm)
        : algorithm_(algorithm), info_(get_algorithm_info(algorithm)) {
        if (0 == info_.key_bits) {
            throw std::invalid_argument("Unsupported algorithm");
        }
    }
} // namespace mpss
