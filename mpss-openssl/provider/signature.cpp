// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/signature.h"
#include <algorithm>
#include <cstddef>
#include <gsl/narrow>
#include <iostream>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/x509v3.h>
#include <string>
#include <string_view>
#include <utility>
#include "mpss-openssl/provider/digest.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/utils/utils.h"

namespace {
    using namespace mpss_openssl::provider;
    using namespace mpss_openssl::utils;

    struct mpss_signature_ctx {
        mpss_key *pkey = nullptr;
        mpss_digest_ctx *dctx = nullptr;
        mpss_provider_ctx *provctx = nullptr;

        ~mpss_signature_ctx();
    };

    mpss_signature_ctx::~mpss_signature_ctx()
    {
        mpss_delete<false>(dctx);
        dctx = nullptr;

        // NOTE: We are *not* supposed to release any of these. They are
        // managed elsewhere.
        pkey = nullptr;
        provctx = nullptr;
    }

    extern "C" void *mpss_signature_newctx(void *provctx, [[maybe_unused]] const char *propq)
    {
        mpss_provider_ctx *ctx = static_cast<mpss_provider_ctx *>(provctx);
        if (!ctx) {
            return nullptr;
        }

        // Create the new signature context.
        mpss_signature_ctx *sctx = mpss_new<mpss_signature_ctx>();
        sctx->provctx = ctx;

        std::cout << "LOG: mpss_sig_newctx (" << sctx << ")" << std::endl;
        return sctx;
    }

    extern "C" void mpss_signature_freectx(void *ctx)
    {
        mpss_delete<false>(static_cast<mpss_signature_ctx *>(ctx));
        std::cout << "LOG: mpss_sig_newctx (" << ctx << ")" << std::endl;
    }

    extern "C" void *mpss_signature_dupctx(void *ctx)
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return nullptr;
        }

        // Create a new signature context.
        mpss_signature_ctx *new_sctx = mpss_new<mpss_signature_ctx>();
        if (!new_sctx) {
            return nullptr;
        }

        // Make a clone of the digest context.
        new_sctx->dctx = static_cast<mpss_digest_ctx *>(mpss_digest_dupctx(sctx->dctx));

        // Copy over the key and provider contexts.
        new_sctx->provctx = sctx->provctx;
        new_sctx->pkey = sctx->pkey;

        std::cout << "LOG: mpss_sig_dupctx (" << new_sctx << ")" << std::endl;
        return new_sctx;
    }

    extern "C" const OSSL_PARAM *mpss_signature_gettable_ctx_params(
        void *ctx, [[maybe_unused]] void *provctx)
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);

        static OSSL_PARAM ret_key_available[] = {
            OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, nullptr, 0), OSSL_PARAM_END
        };

        static OSSL_PARAM ret_key_unavailable[] = { OSSL_PARAM_END };

        if (sctx && sctx->pkey && sctx->pkey->has_valid_key()) {
            return ret_key_available;
        }
        return ret_key_unavailable;
    }

    extern "C" int mpss_signature_get_ctx_params(void *ctx, OSSL_PARAM params[])
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        if (!sctx->pkey || !sctx->pkey->has_valid_key()) {
            // Nothing to return.
            return 1;
        }

        OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (!p) {
            return 0;
        }

        // Get the algorithm ID from the name string we constructed above.
        ASN1_OBJECT *obj = OBJ_txt2obj(sctx->pkey->alg_name->c_str(), 0);
        if (!obj) {
            std::cout << "LOG: mpss_signature_get_ctx_params (failed to create ASN1_OBJECT from "
                      << sctx->pkey->alg_name->c_str() << ")" << std::endl;
            return 0;
        }

        X509_ALGOR *alg = X509_ALGOR_new();
        if (!alg) {
            return 0;
        }
        if (1 != X509_ALGOR_set0(alg, obj, V_ASN1_NULL, nullptr)) {
            X509_ALGOR_free(alg);
            return 0;
        }

        // Get and set the algorithm ID to output parameters.
        unsigned char *alg_der = nullptr;
        int aid_size = i2d_X509_ALGOR(alg, &alg_der);
        if (1 != OSSL_PARAM_set_octet_string(p, alg_der, aid_size)) {
            OPENSSL_free(alg_der);
            X509_ALGOR_free(alg);
            return 0;
        }
        OPENSSL_free(alg_der);
        X509_ALGOR_free(alg);

        std::cout << "LOG: mpss_signature_get_ctx_params" << std::endl;
        return 1;
    }

    extern "C" int mpss_signature_sign_init(
        void *ctx, void *provkey, [[maybe_unused]] const OSSL_PARAM params[])
    {
        // Check that the signature context ctx is not null.
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        // Set the key object and check that it is usable.
        mpss_key *pkey = static_cast<mpss_key *>(provkey);
        if (!pkey || !pkey->has_valid_key()) {
            return 0;
        }
        sctx->pkey = pkey;

        std::cout << "LOG: mpss_signature_sign_init" << std::endl;
        return 1;
    }

    extern "C" int mpss_signature_sign(
        void *ctx,
        unsigned char *sig,
        ::size_t *siglen,
        ::size_t sigsize,
        const unsigned char *tbs,
        ::size_t tbslen,
        [[maybe_unused]] const OSSL_PARAM params[])
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        // Check that the key is valid.
        if (!sctx->pkey || !sctx->pkey->has_valid_key()) {
            return 0;
        }

        // Check that tbs and tbslen are valid.
        std::size_t tbs_expected_bytes = sctx->pkey->key_pair->algorithm_info().hash_bits / 8;
        if (!tbs || tbslen != tbs_expected_bytes) {
            return 0;
        }

        // If sig is nullptr, then we need to write to *siglen an upper bound
        // on the required buffer size and return success.
        std::size_t max_sig_size = mpss_sign_as_der(sctx->pkey->key_pair, {}, {});
        if (!sig) {
            *siglen = max_sig_size;
            return 1;
        }

        // Sign the data. An empty common_byte_vector indicates failure to sign.
        common_byte_vector tbs_bytes(tbslen);
        std::transform(tbs, tbs + tbslen, tbs_bytes.begin(), [](unsigned char c) {
            return static_cast<std::byte>(c);
        });

        common_byte_vector der_sig(max_sig_size);
        std::size_t bytes_written = mpss_sign_as_der(sctx->pkey->key_pair, tbs_bytes, der_sig);
        if (0 == bytes_written) {
            return 0;
        }

        if (sigsize < bytes_written) {
            // The length of the signature must not exceed sigsize.
            return 0;
        }

        // Copy in the DER-encoded signature.
        std::transform(der_sig.begin(), der_sig.begin() + bytes_written, sig, [](std::byte b) {
            return static_cast<unsigned char>(b);
        });

        // siglen must be set to the actual number of bytes written.
        *siglen = bytes_written;

        std::cout << "LOG: mpss_signature_sign" << std::endl;
        return 1;
    }

    extern "C" int mpss_signature_verify_init(
        void *ctx, void *provkey, [[maybe_unused]] const OSSL_PARAM params[])
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        // Set the key object.
        mpss_key *pkey = static_cast<mpss_key *>(provkey);
        if (!pkey || !pkey->has_valid_key()) {
            std::cout << "LOG: mpss_signature_verify_init (invalid key)" << std::endl;
            return 0;
        }
        sctx->pkey = pkey;

        std::cout << "LOG: mpss_signature_verify_init" << std::endl;
        return 1;
    }

    extern "C" int mpss_signature_verify(
        void *ctx,
        const unsigned char *sig,
        ::size_t siglen,
        const unsigned char *tbs,
        ::size_t tbslen)
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx || !sctx->pkey || !sctx->pkey->has_valid_key()) {
            return 0;
        }

        common_byte_vector tbs_bytes(tbslen);
        std::transform(tbs, tbs + tbslen, tbs_bytes.begin(), [](unsigned char c) {
            return static_cast<std::byte>(c);
        });

        common_byte_vector sig_bytes(siglen);
        std::transform(sig, sig + siglen, sig_bytes.begin(), [](unsigned char c) {
            return static_cast<std::byte>(c);
        });

        return verify_der(sctx->pkey->key_pair, tbs_bytes, sig_bytes);
    }

    extern "C" int mpss_signature_digest_sign_init(
        void *ctx, const char *mdname, void *provkey, [[maybe_unused]] const OSSL_PARAM params[])
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        mpss_key *pkey = static_cast<mpss_key *>(provkey);
        if (!pkey || !pkey->has_valid_key()) {
            std::cout << "LOG: mpss_signature_digest_sign_init (invalid key)" << std::endl;
            return 0;
        }

        // Let's make a local copy of the hash name in pkey.
        std::string hash_name = pkey->hash_name.value();

        if (!mdname) {
            return 0;
        }

        // Check that mdname matches the key type.
        if (!are_same_hash(std::string_view(mdname), hash_name)) {
            std::cout << "LOG: mpss_signature_digest_sign_init (mdname " << mdname
                      << " is not supported) -> 0" << std::endl;
            return 0;
        }

        // Create the provider digest context.
        mpss_digest_ctx *dctx =
            static_cast<mpss_digest_ctx *>(mpss_digest_newctx(sctx->provctx, hash_name.c_str()));

        if (1 != mpss_digest_init(dctx, nullptr)) {
            std::cout
                << "LOG: mpss_signature_digest_sign_init (failed to initialize digest context)"
                << std::endl;
            mpss_delete<false>(dctx);
            return 0;
        }

        // We are mostly ready to go. Still need to check if we have
        // an existing provider digest context. If so, we'll delete it.
        if (sctx->dctx) {
            mpss_delete<false>(sctx->dctx);
            sctx->dctx = nullptr;
        }

        // Everything went well, so set the pkey and dctx.
        sctx->pkey = pkey;
        sctx->dctx = dctx;

        std::cout << "LOG: mpss_signature_digest_sign_init" << std::endl;
        return 1;
    }

    extern "C" int mpss_signature_digest_sign_update(
        void *ctx, const unsigned char *data, ::size_t datalen)
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        if (1 != mpss_digest_update(sctx->dctx, data, datalen)) {
            std::cout << "LOG: mpss_signature_digest_sign_update (failed to update digest)"
                      << std::endl;
            return 0;
        }

        std::cout << "LOG: mpss_signature_digest_sign_update" << std::endl;
        return 1;
    }

    extern "C" int mpss_signature_digest_sign_final(
        void *ctx, unsigned char *sig, ::size_t *siglen, ::size_t sigsize)
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        common_byte_vector tbs(EVP_MAX_MD_SIZE);
        std::size_t tbslen = 0;
        unsigned char *digest_ptr = reinterpret_cast<unsigned char *>(tbs.data());
        if (1 != mpss_digest_final(sctx->dctx, digest_ptr, &tbslen, EVP_MAX_MD_SIZE)) {
            std::cout << "LOG: mpss_signature_digest_sign_final (failed to finalize digest)"
                      << std::endl;
            return 0;
        }

        const unsigned char *tbs_ptr = reinterpret_cast<const unsigned char *>(tbs.data());
        return mpss_signature_sign(ctx, sig, siglen, sigsize, tbs_ptr, tbslen, nullptr);
    }

    extern "C" int mpss_signature_digest_sign(
        void *ctx,
        unsigned char *sig,
        ::size_t *siglen,
        ::size_t sigsize,
        const unsigned char *tbs,
        ::size_t tbslen)
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        if (1 != mpss_digest_init(sctx->dctx, nullptr)) {
            return 0;
        }
        if (1 != mpss_signature_digest_sign_update(ctx, tbs, tbslen)) {
            return 0;
        }
        if (1 != mpss_signature_digest_sign_final(ctx, sig, siglen, sigsize)) {
            return 0;
        }

        std::cout << "LOG: mpss_signature_digest_sign" << std::endl;
        return 1;
    }

    extern "C" int mpss_signature_digest_verify_init(
        void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
    {
        // We simply call mpss_signature_digest_sign_init. There is no difference.
        return mpss_signature_digest_sign_init(ctx, mdname, provkey, params);
    }

    extern "C" int mpss_signature_digest_verify_update(
        void *ctx, const unsigned char *data, ::size_t datalen)
    {
        // We simply call mpss_signature_digest_sign_update. There is no difference.
        return mpss_signature_digest_sign_update(ctx, data, datalen);
    }

    extern "C" int mpss_signature_digest_verify_final(
        void *ctx, const unsigned char *sig, ::size_t siglen)
    {
        mpss_signature_ctx *sctx = static_cast<mpss_signature_ctx *>(ctx);
        if (!sctx) {
            return 0;
        }

        if (!sctx->dctx) {
            std::cout << "LOG: mpss_signature_digest_verify_final (no digest context)" << std::endl;
            return 0;
        }

        // Check that the digest context is available and in the right state.
        // This means that the EVP_MD_CTX and EVP_MD are already set up.
        digest_state state = sctx->dctx->state;
        if ((state != digest_state::digesting) && (state != digest_state::finalized)) {
            return 0;
        }

        if (state != digest_state::finalized) {
            common_byte_vector digest(EVP_MAX_MD_SIZE);

            // First, we try to finalize the digest.
            unsigned int bytes_written = 0;
            unsigned char *digest_ptr = reinterpret_cast<unsigned char *>(digest.data());
            if (1 != EVP_DigestFinal_ex(sctx->dctx->evp_dctx, digest_ptr, &bytes_written)) {
                std::cout << "LOG: mpss_signature_digest_verify_final (failed to finalize digest)"
                          << std::endl;
                return 0;
            }

            // Any errors after this are critical and should brick the context.
            sctx->dctx->state = digest_state::finalized;

            std::size_t digest_bytes = 0;
            try {
                digest_bytes = gsl::narrow<std::size_t>(bytes_written);
            } catch (const gsl::narrowing_error &e) {
                // Failed narrow.
                sctx->dctx->state = digest_state::error;
                return 0;
            }

            // Sanity check: does digest_bytes match the expected size?
            std::size_t expected_bytes = sctx->pkey->key_pair->algorithm_info().hash_bits / 8;
            if (digest_bytes != expected_bytes) {
                std::cout << "LOG: mpss_signature_digest_verify_final (digest size mismatch)"
                          << std::endl;
                sctx->dctx->state = digest_state::error;
                return 0;
            }

            // Resize the vector to the correct size and save in the context.
            digest.resize(digest_bytes);
            sctx->dctx->digest = std::move(digest);
        }

        // The digest was successfully finalized, so we can now verify it.
        const unsigned char *tbs =
            reinterpret_cast<const unsigned char *>(sctx->dctx->digest.data());
        std::size_t tbslen = sctx->dctx->digest.size();
        return mpss_signature_verify(ctx, sig, siglen, tbs, tbslen);
    }

    extern "C" int mpss_signature_digest_verify(
        void *ctx,
        const unsigned char *sig,
        ::size_t siglen,
        const unsigned char *tbs,
        ::size_t tbslen)
    {
        if (1 != mpss_signature_digest_verify_update(ctx, tbs, tbslen)) {
            return 0;
        }
        if (1 != mpss_signature_digest_verify_final(ctx, sig, siglen)) {
            return 0;
        }

        std::cout << "LOG: mpss_signature_digest_verify" << std::endl;
        return 1;
    }

    const OSSL_DISPATCH mpss_ecdsa_functions[] = {
        { OSSL_FUNC_SIGNATURE_NEWCTX, reinterpret_cast<void (*)(void)>(mpss_signature_newctx) },
        { OSSL_FUNC_SIGNATURE_FREECTX, reinterpret_cast<void (*)(void)>(mpss_signature_freectx) },
        { OSSL_FUNC_SIGNATURE_DUPCTX, reinterpret_cast<void (*)(void)>(mpss_signature_dupctx) },
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
          reinterpret_cast<void (*)(void)>(mpss_signature_gettable_ctx_params) },
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
          reinterpret_cast<void (*)(void)>(mpss_signature_get_ctx_params) },
        { OSSL_FUNC_SIGNATURE_SIGN_INIT,
          reinterpret_cast<void (*)(void)>(mpss_signature_sign_init) },
        { OSSL_FUNC_SIGNATURE_SIGN, reinterpret_cast<void (*)(void)>(mpss_signature_sign) },
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
          reinterpret_cast<void (*)(void)>(mpss_signature_verify_init) },
        { OSSL_FUNC_SIGNATURE_VERIFY, reinterpret_cast<void (*)(void)>(mpss_signature_verify) },
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_sign_init) },
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_sign_update) },
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_sign_final) },
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_sign) },
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_verify_init) },
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_verify_update) },
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_verify_final) },
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
          reinterpret_cast<void (*)(void)>(mpss_signature_digest_verify) },
        OSSL_DISPATCH_END
    };
} // namespace

namespace mpss_openssl::provider {
    const OSSL_ALGORITHM mpss_signature_algorithms[] = {
        { mpss_sig_names[ECDSA_index], "provider=mpss", mpss_ecdsa_functions },
        { nullptr, nullptr, nullptr }
    };
}