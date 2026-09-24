// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/serialization.h"
#include "mpss/impl/serialization.h"
#include "mpss/mpss.h"
#include "mpss/utils/ossl_ptr.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <openssl/asn1t.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <utility>

namespace
{

using namespace mpss;
using namespace mpss::impl;
using mpss::utils::bio_ptr;
using mpss::utils::evp_pkey_ctx_ptr;
using mpss::utils::evp_pkey_ptr;
using mpss::utils::fn_deleter;
using mpss::utils::ossl_lib_ctx_ptr;
using mpss::utils::ossl_provider_ptr;

constexpr std::uint64_t reference_version = 1;

// OpenSSL's schema owns these fields, including the nested SPKI, as one ASN.1 object.
struct KeyReferenceAsn1
{
    ASN1_INTEGER *version;
    ASN1_UTF8STRING *backend;
    ASN1_UTF8STRING *name;
    ASN1_UTF8STRING *device;
    X509_PUBKEY *public_key;
};

// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-bounds-array-to-pointer-decay,cppcoreguidelines-pro-type-cstyle-cast)
// - OpenSSL's ASN.1 templates generate C arrays and casts.
ASN1_SEQUENCE(KeyReferenceAsn1) = {
    ASN1_SIMPLE(KeyReferenceAsn1, version, ASN1_INTEGER), ASN1_SIMPLE(KeyReferenceAsn1, backend, ASN1_UTF8STRING),
    ASN1_SIMPLE(KeyReferenceAsn1, name, ASN1_UTF8STRING), ASN1_EXP_OPT(KeyReferenceAsn1, device, ASN1_UTF8STRING, 0),
    ASN1_SIMPLE(KeyReferenceAsn1, public_key, X509_PUBKEY)} ASN1_SEQUENCE_END(KeyReferenceAsn1);
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(KeyReferenceAsn1);
// NOLINTEND(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-bounds-array-to-pointer-decay,cppcoreguidelines-pro-type-cstyle-cast)

using reference_ptr = std::unique_ptr<KeyReferenceAsn1, fn_deleter<KeyReferenceAsn1_free>>;

// Keep public-key conversion independent of application providers; unload the provider before its context.
struct HostContext
{
    ossl_lib_ctx_ptr context{OSSL_LIB_CTX_new()};
    ossl_provider_ptr provider{context ? OSSL_PROVIDER_load(context.get(), "default") : nullptr};
};

// SPKI names the public-key parameters, not the hash; each supported set maps to one MPSS suite.
constexpr std::array algorithm_parameters{std::pair{Algorithm::ecdsa_secp256r1_sha256, NID_X9_62_prime256v1},
                                          std::pair{Algorithm::ecdsa_secp384r1_sha384, NID_secp384r1},
                                          std::pair{Algorithm::ecdsa_secp521r1_sha512, NID_secp521r1}};

std::nullopt_t failure(std::string_view message)
{
    utils::log_and_set_error("{}", message);
    return std::nullopt;
}

bool valid_text(std::string_view text, std::size_t limit)
{
    return !text.empty() && limit >= text.size() &&
           std::ranges::all_of(text, [](unsigned char c) { return 0x20 <= c && 0x7e >= c; });
}

bool valid_location(const KeyLocation &location)
{
    // Serialization checks syntax only; resolving the backend or device belongs to KeyPair::Open.
    return valid_text(location.backend_name, 64) && valid_text(location.name, 64) &&
           (!location.device_id || valid_text(*location.device_id, 256));
}

std::string_view text_value(const ASN1_UTF8STRING *value)
{
    if (nullptr == value || 0 >= ASN1_STRING_length(value))
    {
        return {};
    }

    // ASN.1 strings carry their length separately and need not be null-terminated.
    return {reinterpret_cast<const char *>(ASN1_STRING_get0_data(value)),
            static_cast<std::size_t>(ASN1_STRING_length(value))};
}

std::optional<std::vector<std::byte>> encode_der(const KeyReferenceAsn1 *value)
{
    // Measure before allocating; the second call writes into our bounded buffer and advances cursor.
    const auto *asn_value = reinterpret_cast<const ASN1_VALUE *>(value);
    const int size = ASN1_item_i2d(asn_value, nullptr, ASN1_ITEM_rptr(KeyReferenceAsn1));
    if (0 >= size || std::cmp_less(max_reference_size, size))
    {
        return failure("Failed to encode a bounded key reference.");
    }

    std::vector<std::byte> encoded(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(encoded.data());
    if (size != ASN1_item_i2d(asn_value, &cursor, ASN1_ITEM_rptr(KeyReferenceAsn1)))
    {
        return failure("Failed to encode the key reference.");
    }

    return encoded;
}

evp_pkey_ptr public_key_to_host(OSSL_LIB_CTX *libctx, const KeyReference &reference)
{
    // MPSS public bytes must have the size and uncompressed-point prefix required by this algorithm.
    const auto parameters = std::ranges::find(algorithm_parameters, reference.algorithm,
                                              &decltype(algorithm_parameters)::value_type::first);
    if (algorithm_parameters.end() == parameters ||
        utils::get_public_key_size(reference.algorithm) != reference.public_key.size() ||
        std::byte{4} != reference.public_key.front())
    {
        return {};
    }

    const char *group = OBJ_nid2sn(parameters->second);
    std::array params = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char *>(group), 0),
                         OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                           const_cast<std::byte *>(reference.public_key.data()),
                                                           reference.public_key.size()),
                         OSSL_PARAM_construct_end()};
    evp_pkey_ctx_ptr fromdata(EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=default"));
    EVP_PKEY *raw = nullptr;
    if (!fromdata || 1 != EVP_PKEY_fromdata_init(fromdata.get()) ||
        1 != EVP_PKEY_fromdata(fromdata.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.data()))
    {
        return {};
    }

    // Importing the bytes is not enough: require a mathematically valid public key.
    evp_pkey_ptr key(raw);
    const evp_pkey_ctx_ptr check(EVP_PKEY_CTX_new_from_pkey(libctx, key.get(), "provider=default"));
    if (!check || 1 != EVP_PKEY_public_check(check.get()))
    {
        return {};
    }

    return key;
}

bool read_public_key(OSSL_LIB_CTX *libctx, X509_PUBKEY *spki, KeyReference &reference, ReferenceError &error)
{
    // Accept supported named parameters, not explicit parameter definitions from the input.
    ASN1_OBJECT *algorithm = nullptr;
    X509_ALGOR *identifier = nullptr;
    if (1 != X509_PUBKEY_get0_param(&algorithm, nullptr, nullptr, &identifier, spki))
    {
        return false;
    }

    int parameter_type = 0;
    const void *parameter_value = nullptr;
    X509_ALGOR_get0(nullptr, &parameter_type, &parameter_value, identifier);
    if (NID_X9_62_id_ecPublicKey != OBJ_obj2nid(algorithm) || V_ASN1_OBJECT != parameter_type)
    {
        error = ReferenceError::unsupported;
        return false;
    }

    const int parameter_id = OBJ_obj2nid(static_cast<const ASN1_OBJECT *>(parameter_value));
    const auto parameters =
        std::ranges::find(algorithm_parameters, parameter_id, &decltype(algorithm_parameters)::value_type::second);
    if (algorithm_parameters.end() == parameters)
    {
        error = ReferenceError::unsupported;
        return false;
    }

    // X509_PUBKEY has no public unused-bit-count accessor; inspect its BIT STRING with OpenSSL's ASN.1 decoder.
    unsigned char *der = nullptr;
    const int size = i2d_X509_PUBKEY(spki, &der);
    SCOPE_GUARD(OPENSSL_free(der));
    if (0 >= size)
    {
        return false;
    }

    const unsigned char *cursor = der;
    STACK_OF(ASN1_TYPE) *fields = d2i_ASN1_SEQUENCE_ANY(nullptr, &cursor, size);
    SCOPE_GUARD(sk_ASN1_TYPE_pop_free(fields, ASN1_TYPE_free));
    if (nullptr == fields || cursor != der + size || 2 != sk_ASN1_TYPE_num(fields))
    {
        return false;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast) - OpenSSL typed-stack macro.
    const ASN1_TYPE *public_key_field = sk_ASN1_TYPE_value(fields, 1);
    if (nullptr == public_key_field || V_ASN1_BIT_STRING != ASN1_TYPE_get(public_key_field))
    {
        return false;
    }

    const ASN1_BIT_STRING *public_key_bits =
        public_key_field->value.bit_string; // NOLINT(cppcoreguidelines-pro-type-union-access) - type checked above.
    // The supported public-key encodings must be octet-aligned.
    if (nullptr == public_key_bits ||
        ASN1_STRING_FLAG_BITS_LEFT != (public_key_bits->flags & (ASN1_STRING_FLAG_BITS_LEFT | 7)))
    {
        return false;
    }

    // Decode in the isolated context, validate the point, and normalize compressed input to MPSS public bytes.
    cursor = der;
    const evp_pkey_ptr key(d2i_PUBKEY_ex(nullptr, &cursor, size, libctx, "provider=default"));
    if (!key || cursor != der + size)
    {
        return false;
    }

    const evp_pkey_ctx_ptr check(EVP_PKEY_CTX_new_from_pkey(libctx, key.get(), "provider=default"));
    if (!check || 1 != EVP_PKEY_public_check(check.get()) ||
        1 != EVP_PKEY_set_utf8_string_param(key.get(), OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                            OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED))
    {
        return false;
    }

    reference.algorithm = parameters->first;
    reference.public_key.resize(utils::get_public_key_size(reference.algorithm));
    std::size_t written = 0;
    return 1 == EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                                reinterpret_cast<unsigned char *>(reference.public_key.data()),
                                                reference.public_key.size(), &written) &&
           reference.public_key.size() == written && public_key_to_host(libctx, reference);
}

bool is_whitespace(char c)
{
    return ' ' == c || '\t' == c || '\r' == c || '\n' == c || '\v' == c || '\f' == c;
}

} // namespace

namespace mpss
{

std::optional<std::vector<std::byte>> encode_key_reference_der(const KeyReference &reference)
{
    clear_error();
    if (!valid_location(reference.location))
    {
        return failure("Invalid key-reference location: expected bounded printable ASCII fields.");
    }

    HostContext host;
    if (!host.provider)
    {
        return failure("Failed to initialize key-reference public-key validation.");
    }

    const evp_pkey_ptr public_key = public_key_to_host(host.context.get(), reference);
    if (!public_key)
    {
        return failure("The key reference has an unsupported algorithm or invalid public key.");
    }

    // Copy the supplied location and public key into the schema; never reopen a key while serializing it.
    reference_ptr value(KeyReferenceAsn1_new());
    const auto &location = reference.location;
    if (!value || 1 != ASN1_INTEGER_set_uint64(value->version, reference_version) ||
        1 != ASN1_STRING_set(value->backend, location.backend_name.data(),
                             static_cast<int>(location.backend_name.size())) ||
        1 != ASN1_STRING_set(value->name, location.name.data(), static_cast<int>(location.name.size())) ||
        1 != X509_PUBKEY_set(&value->public_key, public_key.get()))
    {
        return failure("Failed to construct the key-reference ASN.1 structure.");
    }

    // Omit an unset device ID rather than encoding an empty string; the schema owns an allocated field.
    if (location.device_id)
    {
        value->device = ASN1_UTF8STRING_new();
        if (nullptr == value->device || 1 != ASN1_STRING_set(value->device, location.device_id->data(),
                                                             static_cast<int>(location.device_id->size())))
        {
            return failure("Failed to encode the key-reference device identifier.");
        }
    }

    return encode_der(value.get());
}

std::optional<KeyReference> impl::decode_key_reference_der(std::span<const std::byte> der, ReferenceError &error)
{
    clear_error();
    error = ReferenceError::malformed;
    if (der.empty() || max_reference_size < der.size())
    {
        return failure("The key-reference DER is empty or exceeds the size limit.");
    }

    // Embedded SPKI decoding can fetch a public-key implementation before semantic validation.
    HostContext host;
    if (!host.provider)
    {
        return failure("Failed to initialize key-reference public-key validation.");
    }

    const auto *begin = reinterpret_cast<const unsigned char *>(der.data());
    const unsigned char *cursor = begin;
    const reference_ptr value(reinterpret_cast<KeyReferenceAsn1 *>(
        ASN1_item_d2i_ex(nullptr, &cursor, static_cast<long>(der.size()), ASN1_ITEM_rptr(KeyReferenceAsn1),
                         host.context.get(), "provider=default")));
    if (!value || cursor != begin + der.size())
    {
        return failure("Malformed key-reference DER or trailing data.");
    }

    // OpenSSL accepts BER too; byte-identical re-encoding rejects noncanonical lengths and forms.
    const auto canonical = encode_der(value.get());
    if (!canonical || !std::ranges::equal(der, *canonical))
    {
        return failure("The key reference is not canonical DER.");
    }

    // Do not interpret an unknown schema version as the version implemented here.
    std::uint64_t version = 0;
    if (1 != ASN1_INTEGER_get_uint64(&version, value->version))
    {
        return failure("Invalid key-reference version.");
    }

    if (reference_version != version)
    {
        error = ReferenceError::unsupported;
        return failure("Unsupported key-reference version.");
    }

    // Copy out owning values before the decoded ASN.1 object is destroyed.
    KeyReference reference;
    reference.location.backend_name = text_value(value->backend);
    reference.location.name = text_value(value->name);
    if (nullptr != value->device)
    {
        reference.location.device_id = text_value(value->device);
    }

    if (!valid_location(reference.location))
    {
        return failure("Invalid key-reference location: expected bounded printable ASCII fields.");
    }

    if (!read_public_key(host.context.get(), value->public_key, reference, error))
    {
        return failure(ReferenceError::unsupported == error ? "Unsupported key-reference public-key algorithm."
                                                            : "Invalid key-reference public key.");
    }

    return reference;
}

std::optional<KeyReference> decode_key_reference_der(std::span<const std::byte> der)
{
    // The public API uses get_error(); the provider also needs the structured failure category.
    impl::ReferenceError error{};
    return impl::decode_key_reference_der(der, error);
}

std::optional<std::string> encode_key_reference_pem(const KeyReference &reference)
{
    const auto der = encode_key_reference_der(reference);
    if (!der)
    {
        return std::nullopt;
    }

    // PEM wraps the same DER bytes in Base64 and delimiters; it introduces no new key representation.
    const bio_ptr out(BIO_new(BIO_s_mem()));
    if (!out ||
        0 >= PEM_write_bio(out.get(), key_reference_pem_label, nullptr,
                           reinterpret_cast<const unsigned char *>(der->data()), static_cast<long>(der->size())))
    {
        return failure("Failed to encode the key-reference PEM.");
    }

    char *data = nullptr;
    const long size = BIO_ctrl(out.get(), BIO_CTRL_INFO, 0, static_cast<void *>(&data));
    if (0 >= size || std::cmp_less(max_reference_pem_size, size))
    {
        return failure("Failed to encode a bounded key-reference PEM.");
    }

    // BIO owns data, so return a copy before releasing it.
    return std::string{data, static_cast<std::size_t>(size)};
}

std::optional<KeyReference> decode_key_reference_pem(std::string_view pem)
{
    clear_error();
    if (pem.empty() || max_reference_pem_size < pem.size())
    {
        return failure("The key-reference PEM is empty or exceeds the size limit.");
    }

    // Accept surrounding whitespace, but require our label at the first non-whitespace line.
    while (!pem.empty() && is_whitespace(pem.front()))
    {
        pem.remove_prefix(1);
    }

    const auto first_newline = pem.find('\n');
    auto first_line = pem.substr(0, first_newline);
    if (first_line.ends_with('\r'))
    {
        first_line.remove_suffix(1);
    }

    if ("-----BEGIN MPSS KEY REFERENCE-----" != first_line || std::string_view::npos == first_newline ||
        std::string_view::npos != pem.find('\0'))
    {
        return failure("Expected an MPSS KEY REFERENCE PEM.");
    }

    // Generic PEM reading returns allocated buffers; reject PEM headers as well as the wrong label.
    const bio_ptr in(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    char *label = nullptr;
    char *header = nullptr;
    unsigned char *data = nullptr;
    long size = 0;
    SCOPE_GUARD(OPENSSL_free(label));
    SCOPE_GUARD(OPENSSL_free(header));
    SCOPE_GUARD(OPENSSL_free(data));
    if (!in || 1 != PEM_read_bio(in.get(), &label, &header, &data, &size) || nullptr == label ||
        key_reference_pem_label != std::string_view{label} || nullptr == header || '\0' != *header || 0 >= size ||
        std::cmp_less(max_reference_size, size))
    {
        return failure("Malformed or unsupported key-reference PEM.");
    }

    // Unlike a stream reader, this API accepts one document only, not a second PEM or trailing text.
    char *remaining = nullptr;
    const long remaining_size = BIO_ctrl(in.get(), BIO_CTRL_INFO, 0, static_cast<void *>(&remaining));
    if (0 > remaining_size ||
        (0 < remaining_size &&
         !std::ranges::all_of(std::string_view{remaining, static_cast<std::size_t>(remaining_size)}, is_whitespace)))
    {
        return failure("Unexpected trailing data after the key-reference PEM.");
    }

    return decode_key_reference_der(std::as_bytes(std::span{data, static_cast<std::size_t>(size)}));
}

} // namespace mpss
