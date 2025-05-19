// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <openssl/core.h>

namespace mpss_openssl::provider {
    struct mpss_provider_ctx {
        const OSSL_CORE_HANDLE *handle;
        OSSL_LIB_CTX *libctx;
    };
} // namespace mpss_openssl::provider
