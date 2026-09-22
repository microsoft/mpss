// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/api.h"
#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/names.h"
#include "mpss-openssl/utils/utils.h"
#include <cstddef>
#include <cstdint>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <span>
#include <utility>

namespace mpss_openssl::provider
{

using namespace ::mpss_openssl::utils;

// The numbers the "storage_tier" parameter reports are the ones api.h names, so a consumer that
// reads them through those constants reads the tier this provider meant. Changing a tier's number
// in either header without the other fails to compile here.
static_assert(static_cast<int>(mpss::StorageTier::unknown) == MPSS_STORAGE_TIER_UNKNOWN);
static_assert(static_cast<int>(mpss::StorageTier::windows_software) == MPSS_STORAGE_TIER_WINDOWS_SOFTWARE);
static_assert(static_cast<int>(mpss::StorageTier::windows_vbs) == MPSS_STORAGE_TIER_WINDOWS_VBS);
static_assert(static_cast<int>(mpss::StorageTier::windows_tpm) == MPSS_STORAGE_TIER_WINDOWS_TPM);
static_assert(static_cast<int>(mpss::StorageTier::apple_keychain) == MPSS_STORAGE_TIER_APPLE_KEYCHAIN);
static_assert(static_cast<int>(mpss::StorageTier::apple_secure_enclave) == MPSS_STORAGE_TIER_APPLE_SECURE_ENCLAVE);
static_assert(static_cast<int>(mpss::StorageTier::android_software) == MPSS_STORAGE_TIER_ANDROID_SOFTWARE);
static_assert(static_cast<int>(mpss::StorageTier::android_unknown_secure) == MPSS_STORAGE_TIER_ANDROID_UNKNOWN_SECURE);
static_assert(static_cast<int>(mpss::StorageTier::android_trusted_environment) ==
              MPSS_STORAGE_TIER_ANDROID_TRUSTED_ENVIRONMENT);
static_assert(static_cast<int>(mpss::StorageTier::android_strongbox) == MPSS_STORAGE_TIER_ANDROID_STRONGBOX);
static_assert(static_cast<int>(mpss::StorageTier::yubikey_piv) == MPSS_STORAGE_TIER_YUBIKEY_PIV);

// A tier appended to the enum needs a constant in api.h, or the provider reports a number no
// consumer of that header can name.
static_assert(static_cast<int>(mpss::StorageTier::count) == MPSS_STORAGE_TIER_YUBIKEY_PIV + 1,
              "a new StorageTier needs an MPSS_STORAGE_TIER_* constant in mpss-openssl/api.h");

// The same for the policy bits the "mpss_key_policy" parameter carries: a caller names a policy
// with the api.h constants and this provider reads the number as a mpss::KeyPolicy, so the two
// spellings have to agree.
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::none) == MPSS_KEY_POLICY_NONE);
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_never) == MPSS_KEY_POLICY_YUBIKEY_PIN_NEVER);
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_once) == MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE);
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_always) == MPSS_KEY_POLICY_YUBIKEY_PIN_ALWAYS);
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_never) == MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER);
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_always) ==
              MPSS_KEY_POLICY_YUBIKEY_TOUCH_ALWAYS);
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_cached) ==
              MPSS_KEY_POLICY_YUBIKEY_TOUCH_CACHED);
static_assert(static_cast<std::uint64_t>(mpss::KeyPolicy::apple_secure_enclave_user_presence) ==
              MPSS_KEY_POLICY_APPLE_SECURE_ENCLAVE_USER_PRESENCE);

// KeyPolicy packs several fields into one number, so a value that does not fit the field it belongs
// to would be read as part of a neighbouring field instead of being rejected. Each field's values
// stay inside its own mask, and the masks stay disjoint.
static_assert((mpss::yubikey_pin_mask & mpss::yubikey_touch_mask) == mpss::KeyPolicy::none,
              "the YubiKey PIN and touch fields must not share bits");
static_assert(
    [] {
        for (const mpss::KeyPolicy pin : {mpss::KeyPolicy::yubikey_pin_never, mpss::KeyPolicy::yubikey_pin_once,
                                          mpss::KeyPolicy::yubikey_pin_always})
        {
            if ((pin & mpss::yubikey_pin_mask) != pin)
            {
                return false;
            }
        }
        for (const mpss::KeyPolicy touch : {mpss::KeyPolicy::yubikey_touch_never, mpss::KeyPolicy::yubikey_touch_always,
                                            mpss::KeyPolicy::yubikey_touch_cached})
        {
            if ((touch & mpss::yubikey_touch_mask) != touch)
            {
                return false;
            }
        }
        return (mpss::KeyPolicy::apple_secure_enclave_user_presence &
                (mpss::yubikey_pin_mask | mpss::yubikey_touch_mask)) == mpss::KeyPolicy::none;
    }(),
    "every KeyPolicy value must fit inside the field it belongs to");

struct mpss_keymgmt_gen_ctx
{
    std::string key_name;
    std::string mpss_algorithm;
    std::optional<std::string> mpss_backend = std::nullopt;
    std::optional<std::string> device_id = std::nullopt;
    std::uint64_t key_policy = 0;
    int selection{0};
};

mpss_key::mpss_key(std::string_view key_name, std::optional<std::string> &mpss_algorithm,
                   const std::optional<std::string> &mpss_backend, mpss::KeyPolicy policy,
                   const std::optional<std::string> &device_id)
{
    // This constructor has a dual purpose. If mpss_algorithm is empty, it tries to open the key with the given name. If
    // mpss_algorithm is not empty, it tries to create a new key with the given name and algorithm.

    if (key_name.empty())
    {
        // If key_name is empty, we cannot create a key.
        return;
    }

    if (!mpss_algorithm)
    {
        // If mpss_algorithm is empty, just try to open the key.
        if (device_id)
        {
            const mpss::KeyLocation location{mpss_backend && !mpss_backend->empty() ? *mpss_backend
                                                                                    : mpss::get_default_backend_name(),
                                             std::string{key_name}, device_id->empty() ? std::nullopt : device_id};
            key_pair = mpss::KeyPair::Open(location);
        }
        else if (mpss_backend)
        {
            key_pair = mpss::KeyPair::Open(key_name, mpss_backend.value());
        }
        else
        {
            key_pair = mpss::KeyPair::Open(key_name);
        }
        if (key_pair)
        {
            // Read the algorithm name from the opened key.
            const std::string mpss_alg_str = key_pair->algorithm_info().type_str;

            // Try to get the canonical name instead.
            mpss_algorithm = try_get_mpss_algorithm_name(mpss_alg_str);

            // Save the algorithm also in a local variable.
            this->mpss_algorithm = mpss_algorithm;
        }
    }
    else
    {
        // If mpss_algorithm is not empty, try to create the key.
        // First, try to get the mpss algorithm.
        const mpss::Algorithm algorithm = try_get_mpss_algorithm(mpss_algorithm.value());

        // Now try to create the key and save the algorithm in a local variable.
        if (mpss::Algorithm::unsupported != algorithm)
        {
            if (device_id)
            {
                const mpss::KeyLocation location{
                    mpss_backend && !mpss_backend->empty() ? *mpss_backend : mpss::get_default_backend_name(),
                    std::string{key_name}, device_id->empty() ? std::nullopt : device_id};
                key_pair = mpss::KeyPair::Create(location, algorithm, policy);
            }
            else if (mpss_backend)
            {
                key_pair = mpss::KeyPair::Create(key_name, algorithm, mpss_backend.value(), policy);
            }
            else
            {
                key_pair = mpss::KeyPair::Create(key_name, algorithm, policy);
            }
            this->mpss_algorithm = mpss::get_algorithm_info(algorithm).type_str;
        }
        else
        {
            this->mpss_algorithm = std::nullopt;
        }

        // Finally, save the canonical algorithm name in a local variable.
    }

    // Save the backend.
    this->mpss_backend = mpss_backend;

    // Try to read the algorithm, group, and hash names from the key.
    name = key_name;
    sig_name = try_get_signature_scheme(key_pair);
    group_name = try_get_ec_group(key_pair);
    hash_name = try_get_hash_func(key_pair);
    alg_name = try_get_algorithm_name(key_pair);
}

mpss_key::mpss_key(std::unique_ptr<mpss::KeyPair> opened_key) : key_pair(std::move(opened_key))
{
    if (!key_pair)
    {
        return;
    }
    const mpss::KeyLocation location = key_pair->location();
    name = location.name;
    mpss_backend = location.backend_name;
    mpss_algorithm = key_pair->algorithm_info().type_str;
    sig_name = try_get_signature_scheme(key_pair);
    group_name = try_get_ec_group(key_pair);
    hash_name = try_get_hash_func(key_pair);
    alg_name = try_get_algorithm_name(key_pair);
}

[[nodiscard]]
bool mpss_key::has_valid_key() const noexcept
{
    return key_pair && (key_pair->algorithm() != mpss::Algorithm::unsupported) && name && sig_name && group_name &&
           hash_name && mpss_algorithm && alg_name;
}

} // namespace mpss_openssl::provider

namespace
{

using namespace ::mpss_openssl::provider;
using namespace ::mpss_openssl::utils;

extern "C" int mpss_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
try
{
    // Ensure that key data is supplied and holds a key.
    mpss_key *pkey = static_cast<mpss_key *>(keydata);
    if (nullptr == pkey || !pkey->has_valid_key())
    {
        return 0;
    }

    // Fail early on any selection requesting the private key.
    if (0 != (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
    {
        return 0;
    }

    // Get the algorithm info.
    const mpss::AlgorithmInfo info = pkey->key_pair->algorithm_info();
    const std::string_view type_str = info.type_str;

    // Capacity: at most 2 params (group name + public key) plus OSSL_PARAM_END terminator.
    OSSL_PARAM params[3]{};
    OSSL_PARAM *p = params;

    // The public key is written in this. It needs to stay alive until the call to
    // param_cb finishes, since it holds the public key buffer.
    byte_vector vk;

    // For a parameter export, we just return the group type string.
    if (0 != (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
    {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - guaranteed by has_valid_key() check above.
        char *group_name = pkey->group_name->data();
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    }

    if (0 != (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
    {
        const std::size_t key_size = pkey->key_pair->extract_key_size();
        if (0 == key_size)
        {
            return 0;
        }

        vk.resize(key_size);
        if (key_size != pkey->key_pair->extract_key(vk))
        {
            return 0;
        }

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, vk.data(), vk.size());
    }

    *p = OSSL_PARAM_END;

    // Call the callback with this and cbarg.
    if (1 != param_cb(params, cbarg))
    {
        return 0;
    }

    return 1;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

extern "C" const OSSL_PARAM *mpss_keymgmt_export_types(int selection)
try
{
    static const OSSL_PARAM no_types[] = {OSSL_PARAM_END};

    static const OSSL_PARAM param_types[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
                                             OSSL_PARAM_END};

    static const OSSL_PARAM key_types[] = {OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0),
                                           OSSL_PARAM_END};

    static const OSSL_PARAM all_types[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
                                           OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0),
                                           OSSL_PARAM_END};

    static const OSSL_PARAM *types_array[] = {no_types, param_types, key_types, all_types};

    // Private key selection is not supported. Return early.
    if (0 != (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
    {
        return types_array[0];
    }

    std::size_t types_idx = 0;
    if (0 != (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
    {
        types_idx += 1;
    }
    if (0 != (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
    {
        types_idx += 2;
    }

    return types_array[types_idx];
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" const OSSL_PARAM *mpss_keymgmt_gen_settable_params([[maybe_unused]] void *genctx,
                                                              [[maybe_unused]] void *provctx)
try
{
    static const OSSL_PARAM ret[] = {
        OSSL_PARAM_utf8_string("mpss_key_name", nullptr, 0), OSSL_PARAM_utf8_string("mpss_algorithm", nullptr, 0),
        OSSL_PARAM_utf8_string("mpss_backend", nullptr, 0),  OSSL_PARAM_utf8_string("mpss_device_id", nullptr, 0),
        OSSL_PARAM_uint64("mpss_key_policy", nullptr),       OSSL_PARAM_END};

    return ret;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" int mpss_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
try
{
    mpss_keymgmt_gen_ctx *ctx = static_cast<mpss_keymgmt_gen_ctx *>(genctx);

    // Return failure if no context is given.
    if (nullptr == ctx)
    {
        return 0;
    }
    if (nullptr == params)
    {
        return 1;
    }

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "mpss_key_name");
    if (nullptr != p)
    {
        if (!get_utf8_parameter(p, ctx->key_name))
        {
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, "mpss_algorithm");
    if (nullptr != p)
    {
        if (!get_utf8_parameter(p, ctx->mpss_algorithm))
        {
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, "mpss_backend");
    if (nullptr != p)
    {
        std::string value;
        if (!get_utf8_parameter(p, value))
        {
            return 0;
        }
        ctx->mpss_backend = std::move(value);
    }

    p = OSSL_PARAM_locate_const(params, "mpss_key_policy");
    if (nullptr != p && !OSSL_PARAM_get_uint64(p, &ctx->key_policy))
    {
        return 0;
    }

    p = OSSL_PARAM_locate_const(params, "mpss_device_id");
    if (nullptr != p)
    {
        std::string value;
        if (!get_utf8_parameter(p, value))
        {
            return 0;
        }
        ctx->device_id = std::move(value);
    }

    return 1;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

extern "C" const OSSL_PARAM *mpss_keymgmt_gettable_params([[maybe_unused]] void *genctx, [[maybe_unused]] void *provctx)
try
{
    static const OSSL_PARAM ret[] = {OSSL_PARAM_utf8_string("mpss_key_name", nullptr, 0),
                                     OSSL_PARAM_utf8_string("mpss_algorithm", nullptr, 0),
                                     OSSL_PARAM_utf8_string("mpss_backend", nullptr, 0),
                                     OSSL_PARAM_utf8_string("mpss_device_id", nullptr, 0),
                                     OSSL_PARAM_int("is_hardware_backed", nullptr),
                                     OSSL_PARAM_int("storage_tier", nullptr),
                                     OSSL_PARAM_utf8_string("storage_description", nullptr, 0),
                                     OSSL_PARAM_int32(OSSL_PKEY_PARAM_BITS, nullptr),
                                     OSSL_PARAM_int32(OSSL_PKEY_PARAM_SECURITY_BITS, nullptr),
                                     OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, nullptr, 0),
                                     OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, nullptr, 0),
                                     OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
                                     OSSL_PARAM_END};

    return ret;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" int mpss_keymgmt_get_params(void *pkey, OSSL_PARAM params[])
try
{
    mpss_key *key = static_cast<mpss_key *>(pkey);

    // Return failure if no key is given.
    if (nullptr == key)
    {
        return 0;
    }

    // Return success if no parameters are given.
    if (nullptr == params)
    {
        return 1;
    }

    const std::string key_name = key->name.value_or("");
    const std::string mpss_algorithm = key->mpss_algorithm.value_or("");
    const char *mpss_backend = key->has_valid_key() ? key->key_pair->backend_name() : "";
    const std::string device_id = key->has_valid_key() ? key->key_pair->location().device_id.value_or("") : "";
    std::int32_t bits = 0;
    std::int32_t security_bits = 0;
    const std::string mandatory_digest{key->hash_name.value_or("")};
    const std::string default_digest{key->hash_name.value_or("")};
    const std::string group_name{key->group_name.value_or("")};

    if (key->has_valid_key())
    {
        const mpss::AlgorithmInfo info = key->key_pair->algorithm_info();
        if (std::in_range<std::int32_t>(info.key_bits))
        {
            bits = static_cast<std::int32_t>(info.key_bits);
        }
        if (std::in_range<std::int32_t>(info.security_bits))
        {
            security_bits = static_cast<std::int32_t>(info.security_bits);
        }
    }

    OSSL_PARAM *p{nullptr};
    if ((p = OSSL_PARAM_locate(params, "mpss_key_name")) && !OSSL_PARAM_set_utf8_string(p, key_name.data()))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, "mpss_algorithm")) && !OSSL_PARAM_set_utf8_string(p, mpss_algorithm.data()))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, "mpss_backend")) && !OSSL_PARAM_set_utf8_string(p, mpss_backend))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, "mpss_device_id")) && !OSSL_PARAM_set_utf8_string(p, device_id.c_str()))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, "is_hardware_backed")) &&
        !OSSL_PARAM_set_int(p, key->key_pair->key_info().is_hardware_backed ? 1 : 0))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, "storage_tier")) &&
        !OSSL_PARAM_set_int(p, static_cast<int>(key->key_pair->key_info().storage_tier)))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, "storage_description")) &&
        !OSSL_PARAM_set_utf8_string(p, key->key_pair->key_info().storage_description))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) && !OSSL_PARAM_set_int32(p, bits))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) && !OSSL_PARAM_set_int32(p, security_bits))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) &&
        !OSSL_PARAM_set_utf8_string(p, mandatory_digest.data()))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) &&
        !OSSL_PARAM_set_utf8_string(p, default_digest.data()))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) &&
        !OSSL_PARAM_set_utf8_string(p, group_name.c_str()))
    {
        return 0;
    }

    return 1;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

extern "C" void mpss_keymgmt_gen_cleanup(void *genctx)
{
    // Delete the context.
    mpss_delete(static_cast<mpss_keymgmt_gen_ctx *>(genctx));
}

extern "C" void *mpss_keymgmt_gen_init([[maybe_unused]] void *provctx, int selection, const OSSL_PARAM params[])
try
{
    // NOTE: We must allow params to be nullptr here.

    // Setting the parameters allocates: a raw pointer would leak the context if that throws.
    mpss_ptr<mpss_keymgmt_gen_ctx> genctx{mpss_new<mpss_keymgmt_gen_ctx>()};
    genctx->selection = selection;

    if (1 != mpss_keymgmt_gen_set_params(genctx.get(), params))
    {
        return nullptr;
    }

    return genctx.release();
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" void mpss_keymgmt_free(void *provkey)
{
    // Delete the (public) key.
    mpss_delete(static_cast<mpss_key *>(provkey));
}

extern "C" void *mpss_keymgmt_gen(void *genctx, [[maybe_unused]] OSSL_CALLBACK *cb, [[maybe_unused]] void *cbarg)
try
{
    using namespace mpss;

    mpss_keymgmt_gen_ctx *ctx = static_cast<mpss_keymgmt_gen_ctx *>(genctx);
    if (nullptr == ctx)
    {
        return nullptr;
    }

    // Check that we are generating a key pair.
    if (!(ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
    {
        return nullptr;
    }

    // The algorithm name must be present; otherwise we cannot create a key.
    if (ctx->mpss_algorithm.empty())
    {
        return nullptr;
    }

    // Set up the new mpss_key struct with the right info.
    std::optional<std::string> mpss_algorithm = ctx->mpss_algorithm;
    const auto policy = static_cast<mpss::KeyPolicy>(ctx->key_policy);
    mpss_key *pkey = mpss_new<mpss_key>(ctx->key_name, mpss_algorithm, ctx->mpss_backend, policy, ctx->device_id);
    if (nullptr == pkey)
    {
        return nullptr;
    }

    if (!pkey->has_valid_key())
    {
        mpss_delete(pkey);
        return nullptr;
    }

    return pkey;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" int mpss_keymgmt_has(const void *provkey, int selection)
try
{
    const mpss_key *pkey = static_cast<const mpss_key *>(provkey);
    if (nullptr == pkey)
    {
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) && !pkey->has_valid_key())
    {
        return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) && !(pkey->name && pkey->mpss_algorithm))
    {
        return 0;
    }

    return 1;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

extern "C" const char *mpss_keymgmt_query_operation_name(int operation_id)
try
{
    switch (operation_id)
    {
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    default:
        return nullptr;
    }
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" void *mpss_keymgmt_load(const void *reference, std::size_t reference_sz)
try
{
    if (nullptr == reference || 0 == reference_sz)
    {
        return nullptr;
    }
    mpss_load_reference parsed;
    mpss_reference_error error = mpss_reference_error::malformed;
    if (!mpss_parse_key_load_reference(
            std::span<const unsigned char>(static_cast<const unsigned char *>(reference), reference_sz), parsed, error))
    {
        ERR_raise(ERR_LIB_PROV,
                  mpss_reference_error::unsupported == error ? PROV_R_NOT_SUPPORTED : PROV_R_BAD_ENCODING);
        return nullptr;
    }

    std::unique_ptr<mpss::KeyPair> opened;
    if (mpss_reference_kind::bound == parsed.kind)
    {
        opened = mpss::KeyPair::Open(parsed.key);
    }
    else if (mpss_reference_kind::default_locator == parsed.kind)
    {
        opened = parsed.key.location.backend_name.empty()
                     ? mpss::KeyPair::Open(parsed.key.location.name)
                     : mpss::KeyPair::Open(parsed.key.location.name, parsed.key.location.backend_name);
    }
    else
    {
        opened = mpss::KeyPair::Open(parsed.key.location);
    }
    mpss_ptr<mpss_key> pkey{mpss_new<mpss_key>(std::move(opened))};
    if (!pkey->has_valid_key())
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_OPERATION_FAIL, "%s", mpss::get_error().c_str());
        return nullptr;
    }

    return pkey.release();
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

const OSSL_DISPATCH mpss_ec_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_EXPORT, reinterpret_cast<void (*)(void)>(mpss_keymgmt_export)},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, reinterpret_cast<void (*)(void)>(mpss_keymgmt_export_types)},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_settable_params)},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_set_params)},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gettable_params)},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_get_params)},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_cleanup)},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen_init)},
    {OSSL_FUNC_KEYMGMT_FREE, reinterpret_cast<void (*)(void)>(mpss_keymgmt_free)},
    {OSSL_FUNC_KEYMGMT_LOAD, reinterpret_cast<void (*)(void)>(mpss_keymgmt_load)},
    {OSSL_FUNC_KEYMGMT_GEN, reinterpret_cast<void (*)(void)>(mpss_keymgmt_gen)},
    {OSSL_FUNC_KEYMGMT_HAS, reinterpret_cast<void (*)(void)>(mpss_keymgmt_has)},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, reinterpret_cast<void (*)(void)>(mpss_keymgmt_query_operation_name)},
    OSSL_DISPATCH_END};

} // namespace

namespace mpss_openssl::provider
{

const OSSL_ALGORITHM mpss_keymgmt_algorithms[] = {
    {ec_key_names, "provider=mpss", mpss_ec_keymgmt_functions, "mpss EC key management"},
    {nullptr, nullptr, nullptr, nullptr}};

int mpss_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    return ::mpss_keymgmt_export(keydata, selection, param_cb, cbarg);
}

} // namespace mpss_openssl::provider
