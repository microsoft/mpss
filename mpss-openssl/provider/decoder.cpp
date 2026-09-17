// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/decoder.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/names.h"
#include "mpss-openssl/utils/ossl_ptr.h"
#include "mpss-openssl/utils/utils.h"
#include <cstddef>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/proverr.h>
#include <span>
#include <string>

namespace
{

using namespace ::mpss_openssl::provider;
using namespace ::mpss_openssl::utils;

// mpss only issues EC keys, so a decoded reference is always an "EC" key object.
constexpr const char *mpss_reference_object_data_type = "EC";

// OSSL_FUNC_decoder_decode: 1 continues the decoder chain, 0 aborts it for every decoder.
constexpr int decoder_continue = 1;
constexpr int decoder_hard_error = 0;

// A foreign object lets the chain continue; our own label with a bad body is an error.
enum class reference_parse_status
{
    not_our_pem,
    invalid_mpss_reference,
    ok,
};

struct mpss_decoder_ctx
{
    const OSSL_CORE_HANDLE *handle{nullptr};
    OSSL_LIB_CTX *libctx{nullptr};
};

extern "C" void *mpss_decoder_newctx(void *provctx)
try
{
    mpss_provider_ctx *pctx = static_cast<mpss_provider_ctx *>(provctx);
    if (nullptr == pctx)
    {
        return nullptr;
    }

    auto *dctx = mpss_new<mpss_decoder_ctx>();
    if (nullptr == dctx)
    {
        return nullptr;
    }

    dctx->handle = pctx->handle;
    dctx->libctx = pctx->libctx;
    return dctx;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return nullptr;
}

extern "C" void mpss_decoder_freectx(void *ctx)
{
    mpss_delete(static_cast<mpss_decoder_ctx *>(ctx));
}

extern "C" int mpss_decoder_does_selection([[maybe_unused]] void *provctx, int selection)
try
{
    if (0 == selection)
    {
        return 1;
    }

    // Decoding a reference opens the key it names, so the result can sign. Answering a public-key
    // request would hand that to a caller asking for public material only; the public key comes from
    // encoding an already opened key, or from its certificate.
    return (0 != (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) ? 1 : 0;
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return 0;
}

reference_parse_status parse_reference_input(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin, byte_vector &load_reference)
{
    bio_ptr in(BIO_new_from_core_bio(libctx, cin));
    if (nullptr == in)
    {
        return reference_parse_status::not_our_pem;
    }

    ERR_set_mark();

    char *pem_name = nullptr;
    char *pem_header = nullptr;
    unsigned char *pem_data = nullptr;
    long pem_data_len = 0;
    const int pem_read = PEM_read_bio(in.get(), &pem_name, &pem_header, &pem_data, &pem_data_len);
    if (0 >= pem_read)
    {
        // Discard the probe's errors and let the chain continue.
        ERR_pop_to_mark();
        return reference_parse_status::not_our_pem;
    }

    // PEM_read_bio allocates all three on success, including the header we never read.
    const openssl_buf_ptr<char> pem_name_owner(pem_name);
    const openssl_buf_ptr<char> pem_header_owner(pem_header);
    const openssl_buf_ptr<unsigned char> pem_data_owner(pem_data);

    const bool is_mpss_reference =
        nullptr != pem_name && 0 == std::strcmp(pem_name, mpss_key_reference_pem_label) && pem_data_len >= 0;
    if (!is_mpss_reference)
    {
        ERR_pop_to_mark();
        return reference_parse_status::not_our_pem;
    }

    // Our object: keep any genuine parse errors.
    ERR_clear_last_mark();

    const std::span<const unsigned char> body{pem_data, static_cast<std::size_t>(pem_data_len)};
    std::string backend;
    std::string key_name;
    if (!mpss_parse_key_load_reference(body, backend, key_name))
    {
        // This aborts the whole decoder chain, so it must leave the caller something to report.
        // Nothing below raises on its own, and the mark was cleared just above.
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING, "PEM label \"%s\" does not carry a usable key load reference",
                       mpss_key_reference_pem_label);
        return reference_parse_status::invalid_mpss_reference;
    }

    const auto body_bytes = std::as_bytes(body);
    load_reference.assign(body_bytes.begin(), body_bytes.end());
    return reference_parse_status::ok;
}

extern "C" int mpss_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, [[maybe_unused]] int selection,
                                   OSSL_CALLBACK *object_cb, void *object_cbarg,
                                   [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK *pw_cb, [[maybe_unused]] void *pw_cbarg)
try
{
    mpss_decoder_ctx *dctx = static_cast<mpss_decoder_ctx *>(ctx);
    if (nullptr == dctx || nullptr == object_cb)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return decoder_hard_error;
    }

    byte_vector reference;
    const reference_parse_status status = parse_reference_input(dctx->libctx, cin, reference);
    if (reference_parse_status::not_our_pem == status)
    {
        return decoder_continue;
    }
    if (reference_parse_status::invalid_mpss_reference == status)
    {
        return decoder_hard_error;
    }

    int object_type = OSSL_OBJECT_PKEY;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type),
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                         const_cast<char *>(mpss_reference_object_data_type), 0),
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, reference.data(), reference.size()),
        OSSL_PARAM_END};
    // object_cb consumes the reference synchronously, so the local outlives the call.
    return object_cb(params, object_cbarg);
}
catch (...)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    return decoder_hard_error;
}

const OSSL_DISPATCH mpss_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, reinterpret_cast<void (*)(void)>(mpss_decoder_newctx)},
    {OSSL_FUNC_DECODER_FREECTX, reinterpret_cast<void (*)(void)>(mpss_decoder_freectx)},
    {OSSL_FUNC_DECODER_DOES_SELECTION, reinterpret_cast<void (*)(void)>(mpss_decoder_does_selection)},
    {OSSL_FUNC_DECODER_DECODE, reinterpret_cast<void (*)(void)>(mpss_decoder_decode)},
    OSSL_DISPATCH_END};

} // namespace

namespace mpss_openssl::provider
{

const OSSL_ALGORITHM mpss_decoder_algorithms[] = {
    {ec_key_names, "provider=mpss,input=pem", mpss_decoder_functions, "mpss EC reference PEM decoder"},
    {nullptr, nullptr, nullptr, nullptr}};

} // namespace mpss_openssl::provider
