// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "mpss-openssl/utils/names.h"
#include "mpss-openssl/utils/utils.h"
#include <mpss/mpss.h>
#include <mutex>
#include <openssl/err.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{
// Forwards a null C string as empty rather than rejecting it here, so the library's own validation
// reports it. Returning early would hand back false with no error set, which the caller cannot
// distinguish from a conclusive negative answer.
constexpr std::string_view as_view(const char *str) noexcept
{
    return nullptr == str ? std::string_view{} : std::string_view{str};
}

// The name-list functions are documented to return a null-terminated array, so a failure still has
// to hand back a valid, empty one.
const char *empty_name_list[] = {nullptr};

// Reported when the last-error buffer itself could not be updated.
constexpr const char *internal_error_message = "Internal error.";
} // namespace

bool mpss_delete_key(const char *key_name)
try
{
    return mpss_openssl::utils::delete_key(as_view(key_name));
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return false;
}

bool mpss_delete_key_from_backend(const char *key_name, const char *backend_name)
try
{
    return mpss_openssl::utils::delete_key(as_view(key_name), as_view(backend_name));
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return false;
}

bool mpss_delete_key_at(const mpss_key_location_t *location)
try
{
    if (nullptr == location)
    {
        // Forward an invalid location so core validation refreshes the MPSS error as well as the OpenSSL queue.
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return mpss::KeyPair::Delete(mpss::KeyLocation{});
    }

    const mpss::KeyLocation value{
        std::string{as_view(location->backend_name)}, std::string{as_view(location->key_name)},
        nullptr == location->device_id ? std::nullopt : std::make_optional(std::string{location->device_id})};

    return mpss::KeyPair::Delete(value);
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return false;
}

bool mpss_is_algorithm_available(const char *algorithm_name)
try
{
    return mpss::is_algorithm_available(mpss_openssl::utils::try_get_mpss_algorithm(as_view(algorithm_name)));
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return false;
}

bool mpss_is_algorithm_available_in_backend(const char *algorithm_name, const char *backend_name)
try
{
    return mpss::is_algorithm_available(mpss_openssl::utils::try_get_mpss_algorithm(as_view(algorithm_name)),
                                        as_view(backend_name));
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return false;
}

const char **mpss_get_available_algorithms()
try
{
    // Rebuilt on every call. The underlying availability query caches positive results only, because a
    // negative can be a transient probe failure; memoizing the list here would make such a failure a
    // permanent, process-wide understatement of what the platform supports.
    static thread_local std::vector<const char *> names;
    names.clear();
    for (const mpss::Algorithm &alg : mpss::get_available_algorithms())
    {
        names.push_back(mpss::get_algorithm_info(alg).type_str);
    }
    names.push_back(nullptr);
    return names.data();
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return empty_name_list;
}

const char *mpss_get_error()
try
{
    // Use thread-local storage to hold a copy of the last std::string.
    static thread_local std::string last_error_str;

    last_error_str = mpss::get_error(); // Update buffer
    return last_error_str.c_str();
}
catch (...)
{
    // The buffer could not be updated, so the message is returned directly. This function is
    // documented never to return nullptr.
    return internal_error_message;
}

bool mpss_has_error()
{
    return mpss::has_error();
}

void mpss_clear_error()
{
    mpss::clear_error();
}

const char **mpss_get_available_backends()
try
{
    // Build a static null-terminated array of string pointers on first call.
    // Backend availability is determined at compile time, so it won't change.
    static std::vector<const char *> ptrs;
    static std::once_flag flag;
    std::call_once(flag, [] {
        ptrs = mpss::get_available_backends();
        ptrs.push_back(nullptr); // null-terminate
    });
    return ptrs.data();
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return empty_name_list;
}

const char *mpss_get_default_backend_name()
try
{
    return mpss::get_default_backend_name();
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return "";
}
