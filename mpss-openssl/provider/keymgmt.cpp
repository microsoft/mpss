// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/utils/utils.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <cstddef>
#include <cstdint>
#include <iostream>

namespace mpss_openssl::provider {
    using namespace ::mpss_openssl::utils;

    struct mpss_keymgmt_gen_ctx {
        std::string key_name;
        std::string mpss_algorithm;
        int selection;
    };

    mpss_key::mpss_key(std::string_view key_name, std::optional<std::string> &mpss_algorithm)
    {
        if (key_name.empty()) {
            // If key_name is empty, we cannot create a key.
            return;
        }
        if (!mpss_algorithm) {
            // If mpss_algorithm is empty, just try to open the key.
            key_pair = mpss::KeyPair::Open(key_name);
            if (key_pair) {
                // Write the algorithm string into the mpss_algorithm.
                mpss_algorithm = key_pair->algorithm_info().type_str;
            }
        } else {
            // If mpss_algorithm is not empty, try to create the key.
            mpss::Algorithm algorithm = mpss::algorithm_from_str(mpss_algorithm.value());
            if (algorithm != mpss::Algorithm::unsupported) {
                key_pair = mpss::KeyPair::Create(key_name, algorithm);
            }
        }

        // Try to read the algorithm, group, and hash names from the key.
        name = key_name;
        sig_name = utils::try_get_signature_scheme(key_pair);
        group_name = utils::try_get_ec_group(key_pair);
        hash_name = utils::try_get_hash_func(key_pair);
        alg_name = utils::try_get_algorithm_name(key_pair);
        this->mpss_algorithm = mpss_algorithm;
    }

    mpss_key::~mpss_key()
    {
        key_pair.release();
        key_pair = nullptr;
    }

    [[nodiscard]] bool mpss_key::has_valid_key() const noexcept
    {
        return key_pair && (key_pair->algorithm() != mpss::Algorithm::unsupported) && name.has_value() &&
               sig_name.has_value() && group_name.has_value() && hash_name.has_value() && mpss_algorithm.has_value() &&
               alg_name.has_value();
    }
} // namespace mpss_openssl::provider

namespace {
    using namespace ::mpss_openssl::provider;
    using namespace ::mpss_openssl::utils;

    extern "C" int mpss_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
    {
        // Ensure that key data is supplied and holds a key.
        mpss_key *pkey = static_cast<mpss_key *>(keydata);
        if (!pkey || !pkey->has_valid_key()) {
            return 0;
        }

        // Get the algorithm info.
        mpss::AlgorithmInfo info = pkey->key_pair->algorithm_info();
        std::string_view type_str = info.type_str;

        OSSL_PARAM params[3]{};
        OSSL_PARAM *p = params;

        // The public key is written in this. It needs to stay alive until the call to
        // param_cb finishes, since it holds the public key buffer.
        byte_vector vk;

        // For a parameter export, we just return the group type string.
        if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) {
            char *group_name = pkey->group_name->data();
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            std::size_t key_size = pkey->key_pair->extract_key_size();
            if (0 == key_size) {
                return 0;
            }

            vk.resize(key_size);
            if (key_size != pkey->key_pair->extract_key(vk)) {
                return 0;
            }

            *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, vk.data(), vk.size());
        }

        *p = OSSL_PARAM_END;

        // Call the callback with this and cbarg.
        if (1 != param_cb(params, cbarg)) {
            return 0;
        }

        return 1;
    }

    extern "C" const OSSL_PARAM *mpss_keymgmt_export_types(int selection)
    {
        static constexpr OSSL_PARAM no_types[] = {OSSL_PARAM_END};

        static constexpr OSSL_PARAM param_types[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0), OSSL_PARAM_END};

        static constexpr OSSL_PARAM key_types[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0), OSSL_PARAM_END};

        static constexpr OSSL_PARAM all_types[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0),
            OSSL_PARAM_END};

        static constexpr const OSSL_PARAM *types_array[] = {no_types, param_types, key_types, all_types};

        std::size_t types_idx = 0;
        if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) {
            types_idx += 1;
        }
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            types_idx += 1;
        }

        return types_array[types_idx];
    }

    extern "C" const OSSL_PARAM *mpss_keymgmt_gen_settable_params([[maybe_unused]] void *provctx)
    {
        static constexpr OSSL_PARAM ret[] = {
            OSSL_PARAM_utf8_string("key_name", nullptr, 0),
            OSSL_PARAM_utf8_string("mpss_algorithm", nullptr, 0),
            OSSL_PARAM_END};

        return ret;
    }

    extern "C" int mpss_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
    {
        mpss_keymgmt_gen_ctx *ctx = static_cast<mpss_keymgmt_gen_ctx *>(genctx);

        // Return failure if no context is given.
        if (!ctx) {
            return 0;
        }

        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "key_name");
        if (nullptr != p) {
            const char *value_str = nullptr;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &value_str)) {
                return 0;
            }
            ctx->key_name = value_str;
        }

        p = OSSL_PARAM_locate_const(params, "mpss_algorithm");
        if (nullptr != p) {
            const char *value_str = nullptr;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &value_str)) {
                return 0;
            }
            ctx->mpss_algorithm = value_str;
        }

        return 1;
    }

    extern "C" const OSSL_PARAM *mpss_keymgmt_gettable_params(
        [[maybe_unused]] void *genctx, [[maybe_unused]] void *provctx)
    {
        static constexpr OSSL_PARAM ret[] = {
            OSSL_PARAM_utf8_string("key_name", nullptr, 0),
            OSSL_PARAM_utf8_string("mpss_algorithm", nullptr, 0),
            OSSL_PARAM_int32(OSSL_PKEY_PARAM_BITS, nullptr),
            OSSL_PARAM_int32(OSSL_PKEY_PARAM_SECURITY_BITS, nullptr),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, nullptr, 0),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, nullptr, 0),
            OSSL_PARAM_END};

        return ret;
    }

    extern "C" int mpss_keymgmt_get_params(void *pkey, OSSL_PARAM params[])
    {
        mpss_key *key = static_cast<mpss_key *>(pkey);

        // Return failure if no key is given.
        if (!key) {
            return 0;
        }

        // Return success if no parameters are given.
        if (!params) {
            return 1;
        }

        std::string key_name = key->name.value_or("");
        std::string mpss_algorithm = key->mpss_algorithm.value_or("");
        std::int32_t bits = 0;
        std::int32_t security_bits = 0;
        std::string mandatory_digest(key->hash_name.value_or(""));
        std::string default_digest(key->hash_name.value_or(""));

        if (key->has_valid_key()) {
            mpss::AlgorithmInfo info = key->key_pair->algorithm_info();
            bits = info.key_bits;
            security_bits = info.security_bits;
        }

        OSSL_PARAM *p;
        if ((p = OSSL_PARAM_locate(params, "key_name")) && !OSSL_PARAM_set_utf8_string(p, key_name.data())) {
            return 0;
        }
        if ((p = OSSL_PARAM_locate(params, "mpss_algorithm")) &&
            !OSSL_PARAM_set_utf8_string(p, mpss_algorithm.data())) {
            return 0;
        }
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) && !OSSL_PARAM_set_int32(p, bits)) {
            return 0;
        }
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) && !OSSL_PARAM_set_int32(p, security_bits)) {
            return 0;
        }
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) &&
            !OSSL_PARAM_set_utf8_string(p, mandatory_digest.data())) {
            return 0;
        }
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) &&
            !OSSL_PARAM_set_utf8_string(p, default_digest.data())) {
            return 0;
        }

        return 1;
    }

    extern "C" void mpss_keymgmt_gen_cleanup(void *genctx)
    {
        // Delete the context.
        mpss_delete(static_cast<mpss_keymgmt_gen_ctx *>(genctx));
    }

    extern "C" void *mpss_keymgmt_gen_init([[maybe_unused]] void *provctx, int selection, const OSSL_PARAM params[])
    {
        // NOTE: We must allow params to be nullptr here.

        mpss_keymgmt_gen_ctx *genctx = mpss_new<mpss_keymgmt_gen_ctx>();
        if (!genctx) {
            return nullptr;
        }

        genctx->selection = selection;

        if (1 != mpss_keymgmt_gen_set_params(genctx, params)) {
            mpss_keymgmt_gen_cleanup(genctx);
            genctx = nullptr;
        }

        return genctx;
    }

    extern "C" void mpss_keymgmt_free(void *provkey)
    {
        // Delete the (public) key.
        mpss_delete(static_cast<mpss_key *>(provkey));
    }

    extern "C" void *mpss_keymgmt_gen(void *genctx, [[maybe_unused]] OSSL_CALLBACK *cb, [[maybe_unused]] void *cbarg)
    {
        using namespace mpss;

        mpss_keymgmt_gen_ctx *ctx = static_cast<mpss_keymgmt_gen_ctx *>(genctx);
        if (!ctx) {
            return nullptr;
        }

        // Check that we are generating a key pair.
        if (!(ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) {
            return nullptr;
        }

        // Set up the new mpss_key struct with the right info.
        std::optional<std::string> mpss_algorithm = ctx->mpss_algorithm;
        mpss_key *pkey = mpss_new<mpss_key>(ctx->key_name, mpss_algorithm);
        if (!pkey) {
            return nullptr;
        }

        // Check that everything went well.
        if (!pkey->has_valid_key()) {
            mpss_delete(pkey);
            return nullptr;
        }

        // If a key already existed, mpss_algorithm now has the algorithm type that was loaded.
        // This has to be the same as the one that was requested, otherwise return nullptr.
        if (mpss_algorithm.value() != ctx->mpss_algorithm) {
            mpss_delete(pkey);
            return nullptr;
        }

        // Key generation succeeded.
        return pkey;
    }

    extern "C" int mpss_keymgmt_has(const void *provkey, int selection)
    {
        const mpss_key *pkey = static_cast<const mpss_key *>(provkey);
        if (!pkey) {
            return 0;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) && !pkey->has_valid_key()) {
            return 0;
        }
        if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) &&
            !(pkey->name.has_value() && pkey->mpss_algorithm.has_value())) {
            return 0;
        }

        return 1;
    }

    extern "C" const char *mpss_keymgmt_query_operation_name(int operation_id)
    {
        switch (operation_id) {
        case OSSL_OP_SIGNATURE:
            return "ECDSA";
        default:
            return nullptr;
        }
    }

    const OSSL_DISPATCH mpss_ecdsa_keymgmt_functions[] = {
        {OSSL_FUNC_KEYMGMT_EXPORT, reinterpret_cast<void (*)(void)>(mpss_keymgmt_export)},
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, reinterpret_cast<void (*)(void)>(mpss_keymgmt_export_types)},
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_settable_params)},
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_set_params)},
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gettable_params)},
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_get_params)},
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_cleanup)},
        {OSSL_FUNC_KEYMGMT_GEN_INIT, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_init)},
        {OSSL_FUNC_KEYMGMT_FREE, reinterpret_cast<void (*)(void)>(mpss_keymgmt_free)},
        {OSSL_FUNC_KEYMGMT_GEN, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen)},
        {OSSL_FUNC_KEYMGMT_HAS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_has)},
        {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, reinterpret_cast<void (*)(void)>(mpss_keymgmt_query_operation_name)},
        OSSL_DISPATCH_END};
} // namespace

namespace mpss_openssl::provider {
    const OSSL_ALGORITHM mpss_keymgmt_algorithms[] = {
        {ec_key_names, "provider=mpss", mpss_ecdsa_keymgmt_functions}, {nullptr, nullptr, nullptr}};

    int mpss_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
    {
        return ::mpss_keymgmt_export(keydata, selection, param_cb, cbarg);
    }
} // namespace mpss_openssl::provider