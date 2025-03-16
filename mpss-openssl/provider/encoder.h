// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <openssl/core.h>
#include <openssl/types.h>

namespace mpss_openssl::provider {
    struct mpss_encoder_ctx {
        const OSSL_CORE_HANDLE* handle;
        OSSL_LIB_CTX* libctx;
    };

    extern const OSSL_ALGORITHM mpss_encoder_algorithms[];
}