// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/utils.h"

#include <cstddef>
#include <string>

#include <openssl/core.h>
#include <openssl/evp.h>
#include <openssl/types.h>

namespace mpss_openssl::provider {
    enum class digest_state {
        uninitialized,
        digesting,
        finalized,
        error
    };

    struct mpss_digest_ctx {
        OSSL_LIB_CTX* libctx = nullptr;
        const char* md_name = nullptr;
        digest_state state = digest_state::uninitialized;
        EVP_MD* evp_md = nullptr;
        EVP_MD_CTX* evp_dctx = nullptr;

        // This is only meaningful if state == digest_state::finalized.
        mpss_openssl::utils::common_byte_vector digest = {};

        mpss_digest_ctx() = default;

        ~mpss_digest_ctx();

        mpss_digest_ctx(const mpss_digest_ctx& copy);
    };

    void* mpss_digest_newctx(void* provctx, const char* mdname);
    int mpss_digest_init(void* ctx, [[maybe_unused]] const OSSL_PARAM params[]);
    void* mpss_digest_dupctx(void* ctx);
    int mpss_digest_update(void* ctx, const unsigned char* in, std::size_t inl);
    int mpss_digest_final(void* ctx, unsigned char* out, std::size_t* outl, std::size_t outsz);

    extern const OSSL_ALGORITHM mpss_digest_algorithms[];
}