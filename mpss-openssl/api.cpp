// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include <memory>
#include <mpss/mpss.h>
#include <string>

extern "C" bool mpss_delete_key(const char *key_name)
{
    if (!key_name) {
        return false;
    }

    // Try to open the key.
    std::unique_ptr<mpss::KeyPair> key_pair = mpss::KeyPair::Open(key_name);
    if (!key_pair) {
        return false;
    }

    // Delete the key.
    if (!key_pair->delete_key()) {
        return false;
    }

    return true;
}

extern "C" MPSS_OPENSSL_DECOR const char *mpss_get_error()
{
    // Use thread-local storage to hold a copy of the last std::string.
    static thread_local std::string last_error_str;

    last_error_str = mpss::get_error(); // Update buffer
    return last_error_str.c_str();
}
