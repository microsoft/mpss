// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/error.h"
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>

namespace
{

// A core passes the same functions to every provider instance it loads.
std::atomic<OSSL_FUNC_core_new_error_fn *> core_new_error{nullptr};
std::atomic<OSSL_FUNC_core_set_error_debug_fn *> core_set_error_debug{nullptr};
std::atomic<OSSL_FUNC_core_vset_error_fn *> core_vset_error{nullptr};
std::atomic<OSSL_FUNC_core_set_error_mark_fn *> core_set_error_mark{nullptr};
std::atomic<OSSL_FUNC_core_clear_last_error_mark_fn *> core_clear_last_error_mark{nullptr};
std::atomic<OSSL_FUNC_core_pop_error_to_mark_fn *> core_pop_error_to_mark{nullptr};

} // namespace

namespace mpss_openssl::provider
{

void use_core_error_functions(const OSSL_DISPATCH *in)
{
    for (; nullptr != in && 0 != in->function_id; ++in)
    {
        switch (in->function_id)
        {
        case OSSL_FUNC_CORE_NEW_ERROR:
            core_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            core_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            core_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            core_set_error_mark = OSSL_FUNC_core_set_error_mark(in);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            core_clear_last_error_mark = OSSL_FUNC_core_clear_last_error_mark(in);
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            core_pop_error_to_mark = OSSL_FUNC_core_pop_error_to_mark(in);
            break;
        default:
            break;
        }
    }
}

// NOLINTNEXTLINE(modernize-avoid-variadic-functions) - the core receives error data as a va_list.
void raise_error(const char *file, int line, const char *func, int lib, int reason, const char *fmt, ...)
{
    va_list args{}; // NOLINT(cppcoreguidelines-pro-type-vararg) - the core receives error data as a va_list.
    va_start(args, fmt);

    OSSL_FUNC_core_new_error_fn *new_error = core_new_error;
    OSSL_FUNC_core_set_error_debug_fn *set_error_debug = core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *vset_error = core_vset_error;
    if (nullptr == new_error || nullptr == set_error_debug || nullptr == vset_error)
    {
        ERR_new();
        ERR_set_debug(file, line, func);
        ERR_vset_error(lib, reason, fmt, args);
    }
    else
    {
        // As with the FIPS provider, the core takes the library from the packed code and needs no handle.
        new_error(nullptr);
        set_error_debug(nullptr, file, line, func);
        vset_error(nullptr, static_cast<std::uint32_t>(ERR_PACK(lib, 0, reason)), fmt, args);
    }

    va_end(args);
}

void set_error_mark()
{
    OSSL_FUNC_core_set_error_mark_fn *set_mark = core_set_error_mark;
    if (nullptr == set_mark)
    {
        ERR_set_mark();
        return;
    }

    set_mark(nullptr);
}

void clear_last_error_mark()
{
    OSSL_FUNC_core_clear_last_error_mark_fn *clear_mark = core_clear_last_error_mark;
    if (nullptr == clear_mark)
    {
        ERR_clear_last_mark();
        return;
    }

    clear_mark(nullptr);
}

void pop_error_to_mark()
{
    OSSL_FUNC_core_pop_error_to_mark_fn *pop_to_mark = core_pop_error_to_mark;
    if (nullptr == pop_to_mark)
    {
        ERR_pop_to_mark();
        return;
    }

    pop_to_mark(nullptr);
}

} // namespace mpss_openssl::provider
