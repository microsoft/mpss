// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <openssl/core.h>
#include <openssl/err.h>

namespace mpss_openssl::provider
{

// Errors and error marks go through the core that loaded the provider, so they reach the application's
// error queue even when the provider links its own copy of libcrypto.
void use_core_error_functions(const OSSL_DISPATCH *in);

void raise_error(const char *file, int line, const char *func, int lib, int reason, const char *fmt, ...);

void set_error_mark();

void clear_last_error_mark();

void pop_error_to_mark();

} // namespace mpss_openssl::provider

// Provider code raises errors with these instead of ERR_raise and ERR_raise_data.
// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg) - the core receives error data as a va_list.
#define MPSS_ERR_RAISE_DATA(lib, reason, ...)                                                                          \
    ::mpss_openssl::provider::raise_error(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, (lib), (reason), __VA_ARGS__)
#define MPSS_ERR_RAISE(lib, reason) MPSS_ERR_RAISE_DATA((lib), (reason), nullptr)
// NOLINTEND(cppcoreguidelines-pro-type-vararg)
