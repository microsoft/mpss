// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <openssl/core.h>

extern "C" bool mpss_delete_key(const char *key_name);

extern "C" bool mpss_is_valid_key(const char *key_name);

extern "C" int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx);