// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/defines.h"
#include <openssl/core.h>

extern "C" MPSS_OPENSSL_DECOR bool mpss_delete_key(const char *key_name);

extern "C" MPSS_OPENSSL_DECOR bool mpss_is_valid_key(const char *key_name);

extern "C" int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx);