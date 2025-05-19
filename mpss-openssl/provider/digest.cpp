// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/digest.h"
#include <algorithm>
#include <cstddef>
#include <gsl/narrow>
#include <iostream>
#include <openssl/core_names.h>
#include <string_view>
#include <utility>
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/utils/utils.h"

namespace mpss_openssl::provider {
    using namespace ::mpss_openssl::utils;

    mpss_digest_ctx::~mpss_digest_ctx()
    {
        if (evp_dctx) {
            EVP_MD_CTX_free(evp_dctx);
            evp_dctx = nullptr;
        }

        if (evp_md) {
            EVP_MD_free(evp_md);
            evp_md = nullptr;
        }

        digest.clear();

        libctx = nullptr;
        md_name = nullptr;
        state = digest_state::uninitialized;
    }

    mpss_digest_ctx::mpss_digest_ctx(const mpss_digest_ctx &copy)
    {
        libctx = copy.libctx;
        md_name = copy.md_name;
        state = copy.state;
        evp_dctx = EVP_MD_CTX_dup(copy.evp_dctx);

        // NOTE: We make an owned copy of the evp_md pointer here.
        // The mpss_digest_ctx destructor will then free it.
        evp_md = EVP_MD_CTX_get1_md(evp_dctx);
    }
} // namespace mpss_openssl::provider

namespace {
    using namespace mpss_openssl::provider;

#define MPSS_MAKE_DIGEST_NEWCTX(digest)                                              \
    extern "C" void *mpss_digest_newctx_##digest(void *provctx)                      \
    {                                                                                \
        mpss_provider_ctx *pctx = static_cast<mpss_provider_ctx *>(provctx);         \
        if (!pctx) {                                                                 \
            return nullptr;                                                          \
        }                                                                            \
        mpss_digest_ctx *dctx = mpss_new<mpss_digest_ctx>();                         \
        dctx->libctx = pctx->libctx;                                                 \
        dctx->md_name = #digest;                                                     \
        std::cout << "LOG: mpss_digest_newctx_digest (" << dctx << ")" << std::endl; \
        return dctx;                                                                 \
    }

    MPSS_MAKE_DIGEST_NEWCTX(SHA256)
    MPSS_MAKE_DIGEST_NEWCTX(SHA384)
    MPSS_MAKE_DIGEST_NEWCTX(SHA512)

    extern "C" void mpss_digest_freectx(void *ctx)
    {
        std::cout << "LOG: mpss_digest_freectx (" << ctx << ")" << std::endl;
        mpss_digest_ctx *dctx = static_cast<mpss_digest_ctx *>(ctx);
        mpss_delete<false>(dctx);
    }

    extern "C" void *mpss_digest_dupctx(void *ctx)
    {
        std::cout << "LOG: mpss_digest_dupctx (" << ctx << ")" << std::endl;
        mpss_digest_ctx *dctx = static_cast<mpss_digest_ctx *>(ctx);
        if (!dctx) {
            return nullptr;
        }

        // Make a clone of the digest context.
        mpss_digest_ctx *new_dctx = mpss_new<mpss_digest_ctx>(*dctx);
        return new_dctx;
    }

    extern "C" int mpss_digest_init(void *ctx, [[maybe_unused]] const OSSL_PARAM params[])
    {
        mpss_digest_ctx *dctx = static_cast<mpss_digest_ctx *>(ctx);
        if (!dctx) {
            return 0;
        }

        // In any case, clear the digest contents.
        dctx->digest.clear();

        // If we are already initialized and not in an error state, clear the internal buffers.
        if (dctx->state != digest_state::uninitialized && dctx->state != digest_state::error) {
            dctx->state = digest_state::uninitialized;

            // We leave the md and evp_dctx pointers alone since they can be reused, but we
            // need to clear the state of evp_dctx.
            EVP_MD_CTX_reset(dctx->evp_dctx);

            std::cout << "LOG: mpss_signature_digest_sign_init (cleared state)" << std::endl;
        } else {
            dctx->state = digest_state::uninitialized;

            // Try to obtain the digest and initialize the EVP digest context.
            EVP_MD *md = EVP_MD_fetch(dctx->libctx, dctx->md_name, nullptr);
            if (!md) {
                std::cout
                    << "LOG: mpss_signature_digest_sign_init (failed to create digest context)"
                    << std::endl;
                return 0;
            }

            EVP_MD_CTX *evp_dctx = EVP_MD_CTX_new();
            if (!evp_dctx) {
                std::cout
                    << "LOG: mpss_signature_digest_sign_init (failed to create digest context)"
                    << std::endl;
                EVP_MD_free(md);
                return 0;
            }

            dctx->evp_md = md;
            dctx->evp_dctx = evp_dctx;
        }

        if (1 != EVP_DigestInit_ex(dctx->evp_dctx, dctx->evp_md, nullptr)) {
            std::cout
                << "LOG: mpss_signature_digest_sign_init (failed to initialize digest context)"
                << std::endl;
            return 0;
        }

        // In any case, now we are ready to digest.
        dctx->state = digest_state::digesting;

        std::cout << "LOG: mpss_digest_init" << std::endl;
        return 1;
    }

    extern "C" int mpss_digest_update(void *ctx, const unsigned char *in, ::size_t inl)
    {
        mpss_digest_ctx *dctx = static_cast<mpss_digest_ctx *>(ctx);

        // Check that the digest context is available and in the right state.
        // This means that the EVP_MD_CTX and EVP_MD are already set up.
        if (!dctx || (dctx->state != digest_state::digesting)) {
            return 0;
        }

        // If no data is given, return success.
        if (!in || 0 == inl) {
            return 1;
        }

        // Otherwise, start digesting.
        if (1 != EVP_DigestUpdate(dctx->evp_dctx, in, inl)) {
            std::cout << "LOG: mpss_digest_update (failed to update digest)" << std::endl;
            return 0;
        }

        std::cout << "LOG: mpss_digest_update" << std::endl;
        return 1;
    }

    extern "C" int mpss_digest_final(void *ctx, unsigned char *out, ::size_t *outl, ::size_t outsz)
    {
        mpss_digest_ctx *dctx = static_cast<mpss_digest_ctx *>(ctx);
        if (!dctx) {
            return 0;
        }

        // Check that the digest context is available and in the right state.
        // This means that the EVP_MD_CTX and EVP_MD are already set up.
        digest_state state = dctx->state;
        if ((state != digest_state::digesting) && (state != digest_state::finalized)) {
            return 0;
        }

        if (state != digest_state::finalized) {
            common_byte_vector digest(EVP_MAX_MD_SIZE);

            // First, we try to finalize the digest.
            unsigned int bytes_written = 0;
            unsigned char *digest_ptr = reinterpret_cast<unsigned char *>(digest.data());
            if (1 != EVP_DigestFinal_ex(dctx->evp_dctx, digest_ptr, &bytes_written)) {
                std::cout << "LOG: mpss_digest_final (failed to finalize digest)" << std::endl;
                return 0;
            }

            // Any errors after this are critical and should brick the context.
            dctx->state = digest_state::finalized;

            std::size_t digest_bytes = 0;
            try {
                digest_bytes = gsl::narrow<std::size_t>(bytes_written);
            } catch (const gsl::narrowing_error &e) {
                // Failed narrow.
                dctx->state = digest_state::error;
                return 0;
            }

            // Sanity check: we should not have exceeded outsz.
            if (outsz < digest_bytes) {
                std::cout << "LOG: mpss_digest_final (output buffer too small)" << std::endl;
                dctx->state = digest_state::error;
                return 0;
            }

            // Resize the vector to the correct size.
            digest.resize(digest_bytes);
            dctx->digest = std::move(digest);
        }

        // We must be in finalized state now, because earlier if we ended up in
        // error state we already returned 0.

        std::transform(dctx->digest.begin(), dctx->digest.end(), out, [](std::byte b) {
            return static_cast<unsigned char>(b);
        });
        *outl = dctx->digest.size();

        std::cout << "LOG: mpss_digest_final" << std::endl;
        return 1;
    }

    int mpss_digest_digest_internal(
        void *ctx,
        const unsigned char *in,
        ::size_t inl,
        unsigned char *out,
        ::size_t *outl,
        ::size_t outsz)
    {
        if (1 != mpss_digest_init(ctx, nullptr) || (1 != mpss_digest_update(ctx, in, inl)) ||
            (1 != mpss_digest_final(ctx, out, outl, outsz))) {
            return 0;
        }

        return 1;
    }

#define MPSS_MAKE_DIGEST_DIGEST(digest)                                     \
    extern "C" int mpss_digest_digest_##digest(                             \
        void *provctx,                                                      \
        const unsigned char *in,                                            \
        ::size_t inl,                                                       \
        unsigned char *out,                                                 \
        ::size_t *outl,                                                     \
        ::size_t outsz)                                                     \
    {                                                                       \
        void *ctx = mpss_digest_newctx_##digest(provctx);                   \
        return mpss_digest_digest_internal(ctx, in, inl, out, outl, outsz); \
    }

    MPSS_MAKE_DIGEST_DIGEST(SHA256)
    MPSS_MAKE_DIGEST_DIGEST(SHA384)
    MPSS_MAKE_DIGEST_DIGEST(SHA512)

    extern "C" const OSSL_PARAM *mpss_digest_gettable_params([[maybe_unused]] void *ctx)
    {
        static constexpr OSSL_PARAM ret[] = { OSSL_PARAM_size_t(
                                                  OSSL_DIGEST_PARAM_BLOCK_SIZE, nullptr),
                                              OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, nullptr),
                                              OSSL_PARAM_END };

        std::cout << "LOG: mpss_digest_gettable_params" << std::endl;
        return ret;
    }

#define MPSS_MAKE_DIGEST_GET_PARAMS(digest, digestsz, blocksz)               \
    extern "C" int mpss_digest_get_params_##digest(OSSL_PARAM params[])      \
    {                                                                        \
        OSSL_PARAM *p;                                                       \
        if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) && \
            !OSSL_PARAM_set_size_t(p, blocksz / 8)) {                        \
            return 0;                                                        \
        }                                                                    \
        if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) &&       \
            !OSSL_PARAM_set_size_t(p, digestsz / 8)) {                       \
            return 0;                                                        \
        }                                                                    \
        std::cout << "LOG: mpss_digest_get_params" << std::endl;             \
        return 1;                                                            \
    }

    MPSS_MAKE_DIGEST_GET_PARAMS(SHA256, 256, 512)
    MPSS_MAKE_DIGEST_GET_PARAMS(SHA384, 384, 1024)
    MPSS_MAKE_DIGEST_GET_PARAMS(SHA512, 512, 1024)

#define MPSS_MAKE_DIGEST_DISPATCH_TABLE(digest, digestsz, blocksz)                           \
    const OSSL_DISPATCH mpss_digest_functions_##digest[] = {                                 \
        { OSSL_FUNC_DIGEST_NEWCTX,                                                           \
          reinterpret_cast<void (*)(void)>(mpss_digest_newctx_##digest) },                   \
        { OSSL_FUNC_DIGEST_FREECTX, reinterpret_cast<void (*)(void)>(mpss_digest_freectx) }, \
        { OSSL_FUNC_DIGEST_DUPCTX, reinterpret_cast<void (*)(void)>(mpss_digest_dupctx) },   \
        { OSSL_FUNC_DIGEST_INIT, reinterpret_cast<void (*)(void)>(mpss_digest_init) },       \
        { OSSL_FUNC_DIGEST_UPDATE, reinterpret_cast<void (*)(void)>(mpss_digest_update) },   \
        { OSSL_FUNC_DIGEST_FINAL, reinterpret_cast<void (*)(void)>(mpss_digest_final) },     \
        { OSSL_FUNC_DIGEST_DIGEST,                                                           \
          reinterpret_cast<void (*)(void)>(mpss_digest_digest_##digest) },                   \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                                  \
          reinterpret_cast<void (*)(void)>(mpss_digest_gettable_params) },                   \
        { OSSL_FUNC_DIGEST_GET_PARAMS,                                                       \
          reinterpret_cast<void (*)(void)>(mpss_digest_get_params_##digest) },               \
        OSSL_DISPATCH_END                                                                    \
    };

    MPSS_MAKE_DIGEST_DISPATCH_TABLE(SHA256, 256, 512)
    MPSS_MAKE_DIGEST_DISPATCH_TABLE(SHA384, 384, 1024)
    MPSS_MAKE_DIGEST_DISPATCH_TABLE(SHA512, 512, 1024)

#define MPSS_MAKE_DIGEST_ALGORITHM(digest) \
    { mpss_hash_names[digest##_index], "provider=mpss", mpss_digest_functions_##digest }
} // namespace

namespace mpss_openssl::provider {
    const OSSL_ALGORITHM mpss_digest_algorithms[] = { MPSS_MAKE_DIGEST_ALGORITHM(SHA256),
                                                      MPSS_MAKE_DIGEST_ALGORITHM(SHA384),
                                                      MPSS_MAKE_DIGEST_ALGORITHM(SHA512),
                                                      { nullptr, nullptr, nullptr } };

    void *mpss_digest_newctx(void *provctx, const char *mdname)
    {
        if (!mdname) {
            return nullptr;
        }

        if (std::string_view(mdname) == OSSL_DIGEST_NAME_SHA2_256) {
            return ::mpss_digest_newctx_SHA256(provctx);
        } else if (std::string_view(mdname) == OSSL_DIGEST_NAME_SHA2_384) {
            return ::mpss_digest_newctx_SHA384(provctx);
        } else if (std::string_view(mdname) == OSSL_DIGEST_NAME_SHA2_512) {
            return ::mpss_digest_newctx_SHA512(provctx);
        } else {
            std::cout << "LOG: mpss_digest_newctx (unsupported digest name: " << mdname << ")"
                      << std::endl;
            return nullptr;
        }
    }

    int mpss_digest_init(void *ctx, [[maybe_unused]] const OSSL_PARAM params[])
    {
        return ::mpss_digest_init(ctx, params);
    }

    void *mpss_digest_dupctx(void *ctx)
    {
        return ::mpss_digest_dupctx(ctx);
    }

    int mpss_digest_update(void *ctx, const unsigned char *in, std::size_t inl)
    {
        return ::mpss_digest_update(ctx, in, inl);
    }

    int mpss_digest_final(void *ctx, unsigned char *out, std::size_t *outl, std::size_t outsz)
    {
        return ::mpss_digest_final(ctx, out, outl, outsz);
    }
} // namespace mpss_openssl::provider