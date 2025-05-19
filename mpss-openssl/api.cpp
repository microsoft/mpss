// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include <iostream>
#include <memory>
#include <mpss/mpss.h>
#include <optional>
#include <string>
#include "mpss-openssl/provider/keymgmt.h"

extern "C" bool mpss_delete_key(const char *key_name)
{
    if (!key_name) {
        return false;
    }

    // Try to open the key.
    std::unique_ptr<mpss::KeyPair> key_pair = mpss::KeyPair::Open(key_name);
    if (!key_pair) {
        std::cout << "LOG: mpss_delete_key (failed to open key)" << std::endl;
        return false;
    }

    // Delete the key.
    if (!key_pair->delete_key()) {
        std::cout << "LOG: mpss_delete_key (failed to delete key)" << std::endl;
        return false;
    }

    std::cout << "LOG: mpss_delete_key (mpss::delete_key " << key_name << " succeeded)"
              << std::endl;
    return true;
}

extern "C" bool mpss_is_valid_key(const char *key_name)
{
    using namespace mpss_openssl::provider;

    if (!key_name) {
        return false;
    }

    // Try to open the key.
    std::optional<std::string> algorithm = std::nullopt;
    mpss_key key(key_name, algorithm);
    return key.has_valid_key();
}