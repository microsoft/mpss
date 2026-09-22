// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/encoder.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/names.h"
#include "mpss-openssl/utils/ossl_ptr.h"
#include "mpss-openssl/utils/utils.h"
#include "mpss/serialization.h"
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <string_view>
#include <utility>

namespace
{

using namespace ::mpss_openssl::provider;
using namespace ::mpss_openssl::utils;

extern "C" void *mpss_encoder_newctx(void *provctx)
try
{
    mpss_provider_ctx *pctx = static_cast<mpss_provider_ctx *>(provctx);
    if (nullptr == pctx)
    {
        return nullptr;
    }

    // Create the new encoder context.
    mpss_encoder_ctx *ectx = mpss_new<mpss_encoder_ctx>();
    if (nullptr == ectx)
    {
        return nullptr;
    }

    // Copy over the core handle and library context.
    ectx->handle = pctx->handle;
    ectx->libctx = pctx->libctx;

    return ectx;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" void mpss_encoder_freectx(void *ctx)
{
    mpss_encoder_ctx *ectx = static_cast<mpss_encoder_ctx *>(ctx);
    mpss_delete(ectx);
}

extern "C" const OSSL_PARAM *mpss_encoder_gettable_params([[maybe_unused]] void *provctx)
try
{
    static const OSSL_PARAM ret[] = {OSSL_PARAM_utf8_string("output", nullptr, 0),
                                     OSSL_PARAM_utf8_string("structure", nullptr, 0), OSSL_PARAM_END};

    return ret;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" int mpss_encoder_get_params(OSSL_PARAM params[])
try
{
    if (nullptr == params)
    {
        return 0;
    }

    OSSL_PARAM *p{nullptr};
    if ((p = OSSL_PARAM_locate(params, "output")) && !OSSL_PARAM_set_utf8_string(p, "DER"))
    {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, "structure")) && !OSSL_PARAM_set_utf8_string(p, "SubjectPublicKeyInfo"))
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

extern "C" int mpss_encoder_does_selection([[maybe_unused]] void *provctx, int selection)
try
{
    // We only support encoding the public key.
    if (EVP_PKEY_PUBLIC_KEY == selection)
    {
        return 1;
    }

    return 0;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

extern "C" int mpss_encoder_encode([[maybe_unused]] void *ctx, OSSL_CORE_BIO *cout, const void *obj_raw,
                                   [[maybe_unused]] const OSSL_PARAM obj_abstract[], int selection,
                                   [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK *cb, [[maybe_unused]] void *cbarg)
try
{
    mpss_encoder_ctx *ectx = static_cast<mpss_encoder_ctx *>(ctx);
    if (nullptr == ectx)
    {
        return 0;
    }

    if (EVP_PKEY_PUBLIC_KEY != selection)
    {
        return 0;
    }

    struct param_cb_data_t
    {
        OSSL_LIB_CTX *libctx{nullptr};
        byte_vector spki;
    } cb_data;
    cb_data.libctx = ectx->libctx;
    cb_data.spki = byte_vector{};

    // This callback reads the key data from a returned OSSL_PARAM into vk.
    OSSL_CALLBACK *param_cb = [](const OSSL_PARAM params[], void *arg) -> int {
        // Read in the param_cb_data.
        param_cb_data_t *param_cb_data = static_cast<param_cb_data_t *>(arg);
        if (nullptr == param_cb_data)
        {
            return 0;
        }

        // This function verifies also that both required parameters are present.
        param_cb_data->spki = mpss_vk_params_to_spki(param_cb_data->libctx, params);

        return param_cb_data->spki.empty() ? 0 : 1;
    };

    if (1 != mpss_keymgmt_export(const_cast<void *>(obj_raw),
                                 OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, param_cb,
                                 &cb_data))
    {
        return 0;
    }

    bio_ptr out(BIO_new_from_core_bio(ectx->libctx, cout));
    if (nullptr == out)
    {
        return 0;
    }

    if (!std::in_range<int>(cb_data.spki.size()))
    {
        return 0;
    }

    const int spki_size = static_cast<int>(cb_data.spki.size());
    return (BIO_write(out.get(), cb_data.spki.data(), spki_size) == spki_size) ? 1 : 0;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

extern "C" int mpss_reference_encoder_does_selection([[maybe_unused]] void *provctx, int selection)
try
{
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? 1 : 0;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

extern "C" int mpss_reference_pem_encoder_encode(void *ctx, OSSL_CORE_BIO *cout, const void *obj_raw,
                                                 [[maybe_unused]] const OSSL_PARAM obj_abstract[], int selection,
                                                 [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK *cb,
                                                 [[maybe_unused]] void *cbarg)
try
{
    mpss_encoder_ctx *ectx = static_cast<mpss_encoder_ctx *>(ctx);
    const mpss_key *pkey = static_cast<const mpss_key *>(obj_raw);
    if (nullptr == ectx || nullptr == pkey || !pkey->has_valid_key() || !pkey->name)
    {
        return 0;
    }
    if (0 == (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
    {
        return 0;
    }

    const auto reference = pkey->key_pair->reference();
    if (!reference)
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_OPERATION_FAIL, "%s", mpss::get_error().c_str());
        return 0;
    }
    const auto pem = mpss::encode_key_reference_pem(*reference);
    if (!pem)
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_OPERATION_FAIL, "%s", mpss::get_error().c_str());
        return 0;
    }

    bio_ptr out(BIO_new_from_core_bio(ectx->libctx, cout));
    if (nullptr == out)
    {
        return 0;
    }

    const int size = static_cast<int>(pem->size());
    return size == BIO_write(out.get(), pem->data(), size) ? 1 : 0;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

const OSSL_DISPATCH mpss_ec_reference_pem_encoder_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, reinterpret_cast<void (*)(void)>(mpss_encoder_newctx)},
    {OSSL_FUNC_ENCODER_FREECTX, reinterpret_cast<void (*)(void)>(mpss_encoder_freectx)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, reinterpret_cast<void (*)(void)>(mpss_reference_encoder_does_selection)},
    {OSSL_FUNC_ENCODER_ENCODE, reinterpret_cast<void (*)(void)>(mpss_reference_pem_encoder_encode)},
    OSSL_DISPATCH_END};

const OSSL_DISPATCH mpss_ec_encoder_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, reinterpret_cast<void (*)(void)>(mpss_encoder_newctx)},
    {OSSL_FUNC_ENCODER_FREECTX, reinterpret_cast<void (*)(void)>(mpss_encoder_freectx)},
    {OSSL_FUNC_ENCODER_GETTABLE_PARAMS, reinterpret_cast<void (*)(void)>(mpss_encoder_gettable_params)},
    {OSSL_FUNC_ENCODER_GET_PARAMS, reinterpret_cast<void (*)(void)>(mpss_encoder_get_params)},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, reinterpret_cast<void (*)(void)>(mpss_encoder_does_selection)},
    {OSSL_FUNC_ENCODER_ENCODE, reinterpret_cast<void (*)(void)>(mpss_encoder_encode)},
    OSSL_DISPATCH_END};

} // namespace

namespace mpss_openssl::provider
{

const OSSL_ALGORITHM mpss_encoder_algorithms[] = {
    {ec_encoder_names, "provider=mpss,output=der,structure=SubjectPublicKeyInfo", mpss_ec_encoder_functions,
     "mpss EC SPKI DER encoder"},
    {ec_encoder_names, "provider=mpss,output=pem,structure=MpssKeyReference", mpss_ec_reference_pem_encoder_functions,
     "mpss EC reference PEM encoder"},
    {nullptr, nullptr, nullptr, nullptr}};
}
