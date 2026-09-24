// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/decoder.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/names.h"
#include "mpss-openssl/utils/utils.h"
#include "mpss/serialization.h"
#include "mpss/utils/ossl_ptr.h"
#include <array>
#include <cstddef>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace ::mpss_openssl::provider;
using namespace ::mpss_openssl::utils;
using mpss::utils::bio_ptr;

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

using pem_buffer = std::array<char, mpss_max_reference_pem_size>;

reference_parse_status read_reference_pem(BIO *in, pem_buffer &buffer, std::string_view &pem)
{
    const std::string begin = "-----BEGIN " + std::string{mpss_key_reference_pem_label} + "-----";
    std::optional<std::size_t> begin_offset;
    std::size_t used = 0;
    std::size_t line_start = 0;

    // Ignore probe errors for foreign input; recognizing our label commits us to reporting failures.
    ERR_set_mark();

    // Read bytes, not BIO_gets fragments: file BIOs can underreport lengths containing NUL.
    // The small fixed budget bounds the work; byte reads avoid consuming the following PEM record.
    while (mpss_max_reference_pem_size > used)
    {
        std::size_t count = 0;
        const bool read_failed = 1 != BIO_read_ex(in, buffer.data() + used, 1, &count);
        if (read_failed)
        {
            // The core BIO forwards the underlying EOF status, but not its retry flags.
            if (!BIO_eof(in))
            {
                break;
            }
        }
        else
        {
            used += count;
            if (0 == count || '\0' == buffer[used - 1])
            {
                break;
            }
            if ('\n' != buffer[used - 1])
            {
                continue;
            }
        }

        // Interpret delimiters only at a physical newline or confirmed EOF, never a short-read boundary.
        std::string_view line{buffer.data() + line_start, used - line_start};
        while (!line.empty() && ('\r' == line.back() || '\n' == line.back()))
        {
            line.remove_suffix(1);
        }

        if (!begin_offset && line.starts_with("-----BEGIN "))
        {
            if (line != begin)
            {
                ERR_pop_to_mark();
                return reference_parse_status::not_our_pem;
            }

            begin_offset = line_start;
            ERR_clear_last_mark();
        }
        else if (begin_offset && line.starts_with("-----END "))
        {
            // Stop at the first closing boundary; OpenSSL checks its label and decodes the body.
            pem = {buffer.data() + *begin_offset, used - *begin_offset};
            return reference_parse_status::ok;
        }

        line_start = used;
        if (read_failed)
        {
            break;
        }
    }

    if (!begin_offset)
    {
        ERR_pop_to_mark();
        return reference_parse_status::not_our_pem;
    }

    // A footer reaching the byte limit without LF is incomplete: confirming EOF would require another read.
    ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING, "Invalid, incomplete, or oversized MPSS reference PEM");
    return reference_parse_status::invalid_mpss_reference;
}

reference_parse_status parse_reference_input(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin, byte_vector &load_reference)
{
    bio_ptr in(BIO_new_from_core_bio(libctx, cin));
    if (!in)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return reference_parse_status::invalid_mpss_reference;
    }

    // Frame one bounded record without consuming the next; this does not parse ASN.1 or Base64.
    pem_buffer buffer{};
    std::string_view pem;
    const reference_parse_status status = read_reference_pem(in.get(), buffer, pem);
    if (reference_parse_status::ok != status)
    {
        return status;
    }

    // The same decoder serves the C++ API, so the provider accepts exactly the PEMs the library accepts.
    mpss_reference_error error = mpss_reference_error::malformed;
    const std::optional<mpss::KeyReference> reference = mpss::impl::decode_key_reference_pem(pem, error);
    if (!reference)
    {
        ERR_raise_data(ERR_LIB_PROV,
                       mpss_reference_error::unsupported == error ? PROV_R_NOT_SUPPORTED : PROV_R_BAD_ENCODING,
                       "PEM label \"%s\" does not carry a usable key load reference: %s", mpss_key_reference_pem_label,
                       mpss::get_error().c_str());
        return reference_parse_status::invalid_mpss_reference;
    }

    // Key management receives a self-contained byte reference, so the decoded reference travels as its
    // canonical DER.
    std::optional<byte_vector> der = mpss::encode_key_reference_der(*reference);
    if (!der)
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "%s", mpss::get_error().c_str());
        return reference_parse_status::invalid_mpss_reference;
    }

    load_reference = std::move(*der);
    return reference_parse_status::ok;
}

extern "C" int mpss_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
                                   void *object_cbarg, [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                   [[maybe_unused]] void *pw_cbarg)
try
{
    mpss_decoder_ctx *dctx = static_cast<mpss_decoder_ctx *>(ctx);
    if (nullptr == dctx || nullptr == object_cb)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return decoder_hard_error;
    }
    if (0 != selection && 0 == (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
    {
        return decoder_continue;
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
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, const_cast<char *>(ec_data_type), 0),
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, reference.data(), reference.size()),
        OSSL_PARAM_END};
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
