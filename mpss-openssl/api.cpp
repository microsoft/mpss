// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "mpss-openssl/utils/names.h"
#include <memory>
#include <mpss/mpss.h>
#include <mutex>
#include <string>
#include <vector>

bool mpss_delete_key(const char *key_name)
{
    if (nullptr == key_name)
    {
        return false;
    }

    // Try to open the key.
    const std::unique_ptr<mpss::KeyPair> key_pair = mpss::KeyPair::Open(key_name);
    if (nullptr == key_pair)
    {
        return false;
    }

    // Delete the key.
    if (!key_pair->delete_key())
    {
        return false;
    }

    return true;
}

bool mpss_is_algorithm_available(const char *algorithm_name)
{
    if (nullptr == algorithm_name)
    {
        return false;
    }
    const mpss::Algorithm algorithm = mpss_openssl::utils::try_get_mpss_algorithm(algorithm_name);
    if (mpss::Algorithm::unsupported == algorithm)
    {
        return false;
    }
    return mpss::is_algorithm_available(algorithm);
}

const char **mpss_get_available_algorithms()
{
    // Build a static null-terminated array of string pointers on first call.
    // The algorithm name strings are compile-time constants, so no ownership issues.
    static std::vector<const char *> cache;
    static std::once_flag flag;
    std::call_once(flag, []() {
        for (const mpss::Algorithm &alg : mpss::get_available_algorithms())
        {
            cache.push_back(mpss::get_algorithm_info(alg).type_str);
        }
        cache.push_back(nullptr); // null-terminate
    });
    return cache.data();
}

const char *mpss_get_error()
{
    // Use thread-local storage to hold a copy of the last std::string.
    static thread_local std::string last_error_str;

    last_error_str = mpss::get_error(); // Update buffer
    return last_error_str.c_str();
}

const char **mpss_get_available_backends()
{
    // Build a static null-terminated array of string pointers on first call.
    // Backend availability is determined at compile time, so it won't change.
    static std::vector<const char *> ptrs;
    static std::once_flag flag;
    std::call_once(flag, []() {
        static std::vector<std::string> names = mpss::get_available_backends();
        for (const std::string &name : names)
        {
            ptrs.push_back(name.c_str());
        }
        ptrs.push_back(nullptr); // null-terminate
    });
    return ptrs.data();
}

const char *mpss_get_default_backend_name()
{
    static std::string name;

    name = mpss::get_default_backend_name();
    return name.c_str();
}
