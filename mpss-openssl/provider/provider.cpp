// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/digest.h"
#include "mpss-openssl/provider/encoder.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/provider/signature.h"
#include "mpss-openssl/utils/utils.h"

#include <iostream>

#include <openssl/core_dispatch.h>

namespace {
    using namespace ::mpss_openssl::provider;
    using namespace ::mpss_openssl::util;

    extern "C" void mpss_provider_teardown(void* provctx) {
        mpss_provider_ctx* ctx = static_cast<mpss_provider_ctx*>(provctx);
        OSSL_LIB_CTX_free(ctx->libctx);
        mpss_delete<false>(ctx);
    }

    extern "C" const OSSL_ALGORITHM* mpss_provider_query_operation([[maybe_unused]] void* provctx, int operation_id, int* no_store)
    {
        // The function arrays can be stored by the core.
        if (!no_store) {
            return nullptr;
        }
        *no_store = 0;

        switch (operation_id) {
        case OSSL_OP_KEYMGMT:
            return mpss_keymgmt_algorithms;
        case OSSL_OP_ENCODER:
            return mpss_encoder_algorithms;
        case OSSL_OP_SIGNATURE:
            return mpss_signature_algorithms;
        case OSSL_OP_DIGEST:
            return mpss_digest_algorithms;
        default:
            return nullptr;
        }
    }

    constexpr OSSL_DISPATCH mpss_provider_functions[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN, reinterpret_cast<void(*)(void)>(mpss_provider_teardown) },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, reinterpret_cast<void(*)(void)>(mpss_provider_query_operation) },
        OSSL_DISPATCH_END
    };
}

extern "C" int OSSL_provider_init(const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in, const OSSL_DISPATCH** out, void** provctx)
{
    using namespace mpss_openssl::provider;
    using namespace mpss_openssl::utils;

    mpss_provider_ctx* ctx = mpss_new<mpss_provider_ctx>();
    ctx->handle = handle;

    // Create a new library context from the provider dispatch table.
    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (!libctx) {
        std::cout << "LOG: Failed to create library context." << std::endl;
        return 0;
    }
    ctx->libctx = libctx;

    *provctx = ctx;
    *out = mpss_provider_functions;

    std::cout << "LOG: mpss provider initialized (" << ctx << ")" << std::endl;
    return 1;
}