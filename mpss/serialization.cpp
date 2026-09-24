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
using mpss::utils::openssl_buf_ptr;

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

// SPKI names the public-key parameters, not the hash; each supported set maps to one MPSS suite.
constexpr std::array algorithm_parameters{std::pair{Algorithm::ecdsa_secp256r1_sha256, NID_X9_62_prime256v1},
                                          std::pair{Algorithm::ecdsa_secp384r1_sha384, NID_secp384r1},
                                          std::pair{Algorithm::ecdsa_secp521r1_sha512, NID_secp521r1}};

// OpenSSL keeps a BIT STRING's unused-bit count in these flag bits.
constexpr unsigned long unused_bits_flags = ASN1_STRING_FLAG_BITS_LEFT | 7U;

// Public keys are validated in a private context, so the application's providers and default properties
// cannot affect the result. Immortal like BackendRegistry::Instance(): never freed, so it outlives host
// statics that serialize during exit; OSSL_LIB_CTX use is thread-safe.
[[nodiscard]]
OSSL_LIB_CTX *host_context()
{
    static OSSL_LIB_CTX *const context = [] {
        OSSL_LIB_CTX *created = OSSL_LIB_CTX_new();
        if (nullptr != created && nullptr == OSSL_PROVIDER_load(created, "default"))
        {
            OSSL_LIB_CTX_free(created);
            created = nullptr;
        }

        return created;
    }();
    return context;
}

[[nodiscard]]
std::nullopt_t failure(std::string_view message)
{
    utils::log_and_set_error("{}", message);
    return std::nullopt;
}

[[nodiscard]]
bool valid_text(std::string_view text, std::size_t limit)
{
    return !text.empty() && limit >= text.size() &&
           std::ranges::all_of(text, [](unsigned char c) { return 0x20 <= c && 0x7e >= c; });
}

[[nodiscard]]
bool valid_location(const KeyLocation &location)
{
    // Serialization checks syntax only; resolving the backend or device belongs to KeyPair::Open.
    return valid_text(location.backend_name, 64) && valid_text(location.name, 64) &&
           (!location.device_id || valid_text(*location.device_id, 256));
}

[[nodiscard]]
std::string_view text_value(const ASN1_UTF8STRING *value)
{
    if (nullptr == value || 0 >= ASN1_STRING_length(value))
    {
        return {};
    }

    return {reinterpret_cast<const char *>(ASN1_STRING_get0_data(value)),
            static_cast<std::size_t>(ASN1_STRING_length(value))};
}

[[nodiscard]]
std::optional<std::vector<std::byte>> encode_der(const KeyReferenceAsn1 *value)
{
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

[[nodiscard]]
int group_nid(Algorithm algorithm)
{
    const auto parameters =
        std::ranges::find(algorithm_parameters, algorithm, [](const auto &entry) { return entry.first; });
    return algorithm_parameters.end() == parameters ? NID_undef : parameters->second;
}

[[nodiscard]]
bool valid_public_key(OSSL_LIB_CTX *libctx, const KeyReference &reference)
{
    // MPSS public bytes must have the size and uncompressed-point prefix required by this algorithm.
    const int nid = group_nid(reference.algorithm);
    if (NID_undef == nid || reference.public_key.empty() ||
        utils::get_public_key_size(reference.algorithm) != reference.public_key.size() ||
        std::byte{4} != reference.public_key.front())
    {
        return false;
    }

    const char *group = OBJ_nid2sn(nid);
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
        return false;
    }

    // Importing the bytes is not enough: require a mathematically valid public key.
    const evp_pkey_ptr key(raw);
    const evp_pkey_ctx_ptr check(EVP_PKEY_CTX_new_from_pkey(libctx, key.get(), "provider=default"));
    return check && 1 == EVP_PKEY_public_check(check.get());
}

[[nodiscard]]
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
        std::ranges::find(algorithm_parameters, parameter_id, [](const auto &entry) { return entry.second; });
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

    // The supported public-key encodings must be octet-aligned; ASN1_TYPE_get reports a type only with a value.
    const ASN1_BIT_STRING *public_key_bits =
        public_key_field->value.bit_string; // NOLINT(cppcoreguidelines-pro-type-union-access) - type checked above.
    if (ASN1_STRING_FLAG_BITS_LEFT != (static_cast<unsigned long>(public_key_bits->flags) & unused_bits_flags))
    {
        return false;
    }

    // Decode in the private context, validate the point, and normalize compressed or hybrid input to MPSS
    // public bytes.
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
           reference.public_key.size() == written && valid_public_key(libctx, reference);
}

[[nodiscard]]
bool is_whitespace(char c)
{
    return ' ' == c || '\t' == c || '\r' == c || '\n' == c || '\v' == c || '\f' == c;
}

[[nodiscard]]
std::string_view trim(std::string_view text)
{
    while (!text.empty() && is_whitespace(text.front()))
    {
        text.remove_prefix(1);
    }

    while (!text.empty() && is_whitespace(text.back()))
    {
        text.remove_suffix(1);
    }

    return text;
}

[[nodiscard]]
std::optional<std::string> write_pem(std::span<const std::byte> der)
{
    const bio_ptr out(BIO_new(BIO_s_mem()));
    if (!out || 0 >= PEM_write_bio(out.get(), key_reference_pem_label, nullptr,
                                   reinterpret_cast<const unsigned char *>(der.data()), static_cast<long>(der.size())))
    {
        return std::nullopt;
    }

    char *data = nullptr;
    const long size = BIO_ctrl(out.get(), BIO_CTRL_INFO, 0, static_cast<void *>(&data));
    if (0 >= size || std::cmp_less(max_reference_pem_size, size))
    {
        return std::nullopt;
    }

    return std::string{data, static_cast<std::size_t>(size)};
}

// PEM reading tolerates headers, stray bytes, and noncanonical Base64; the decoded bytes must reproduce the
// trimmed input, allowing only CRLF in place of LF.
[[nodiscard]]
bool is_canonical_pem(std::string_view pem, std::span<const std::byte> der)
{
    const auto canonical = write_pem(der);
    if (!canonical)
    {
        return false;
    }

    std::string normalized;
    normalized.reserve(pem.size());
    for (std::size_t i = 0; i < pem.size(); ++i)
    {
        const bool crlf = '\r' == pem[i] && i + 1 < pem.size() && '\n' == pem[i + 1];
        if (!crlf)
        {
            normalized.push_back(pem[i]);
        }
    }

    return trim(*canonical) == normalized;
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

    OSSL_LIB_CTX *host = host_context();
    if (nullptr == host)
    {
        return failure("Failed to initialize key-reference public-key validation.");
    }

    if (!valid_public_key(host, reference))
    {
        return failure("The key reference has an unsupported algorithm or invalid public key.");
    }

    // Set the SPKI fields directly: converting an EVP_PKEY would decode it in the application's default context.
    // OBJ_nid2obj returns static objects, which the structure holds without owning them.
    reference_ptr value(KeyReferenceAsn1_new());
    openssl_buf_ptr<unsigned char> point(
        static_cast<unsigned char *>(OPENSSL_memdup(reference.public_key.data(), reference.public_key.size())));
    const auto &location = reference.location;
    if (!value || !point || 1 != ASN1_INTEGER_set_uint64(value->version, reference_version) ||
        1 != ASN1_STRING_set(value->backend, location.backend_name.data(),
                             static_cast<int>(location.backend_name.size())) ||
        1 != ASN1_STRING_set(value->name, location.name.data(), static_cast<int>(location.name.size())) ||
        1 != X509_PUBKEY_set0_param(value->public_key, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), V_ASN1_OBJECT,
                                    OBJ_nid2obj(group_nid(reference.algorithm)), point.get(),
                                    static_cast<int>(reference.public_key.size())))
    {
        return failure("Failed to construct the key-reference ASN.1 structure.");
    }

    static_cast<void>(point.release());
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
    OSSL_LIB_CTX *host = host_context();
    if (nullptr == host)
    {
        return failure("Failed to initialize key-reference public-key validation.");
    }

    const auto *begin = reinterpret_cast<const unsigned char *>(der.data());
    const unsigned char *cursor = begin;
    const reference_ptr value(reinterpret_cast<KeyReferenceAsn1 *>(ASN1_item_d2i_ex(
        nullptr, &cursor, static_cast<long>(der.size()), ASN1_ITEM_rptr(KeyReferenceAsn1), host, "provider=default")));
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

    // A negative version is malformed; any other unknown version, including one beyond 64 bits, is unsupported.
    if (V_ASN1_NEG_INTEGER == ASN1_STRING_type(value->version))
    {
        return failure("Invalid key-reference version.");
    }

    std::uint64_t version = 0;
    if (1 != ASN1_INTEGER_get_uint64(&version, value->version) || reference_version != version)
    {
        error = ReferenceError::unsupported;
        return failure("Unsupported key-reference version.");
    }

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

    if (!read_public_key(host, value->public_key, reference, error))
    {
        return failure(ReferenceError::unsupported == error ? "Unsupported key-reference public-key algorithm."
                                                            : "Invalid key-reference public key.");
    }

    return reference;
}

std::optional<KeyReference> decode_key_reference_der(std::span<const std::byte> der)
{
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

    auto pem = write_pem(*der);
    if (!pem)
    {
        return failure("Failed to encode the key-reference PEM.");
    }

    return pem;
}

std::optional<KeyReference> impl::decode_key_reference_pem(std::string_view pem, ReferenceError &error)
{
    clear_error();
    error = ReferenceError::malformed;
    if (pem.empty() || max_reference_pem_size < pem.size())
    {
        return failure("The key-reference PEM is empty or exceeds the size limit.");
    }

    pem = trim(pem);
    if (!pem.starts_with("-----BEGIN MPSS KEY REFERENCE-----"))
    {
        return failure("Expected an MPSS KEY REFERENCE PEM.");
    }

    const bio_ptr in(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    char *label = nullptr;
    char *header = nullptr;
    unsigned char *data = nullptr;
    long size = 0;
    SCOPE_GUARD(OPENSSL_free(label));
    SCOPE_GUARD(OPENSSL_free(header));
    SCOPE_GUARD(OPENSSL_free(data));
    if (!in || 1 != PEM_read_bio(in.get(), &label, &header, &data, &size) || 0 >= size ||
        std::cmp_less(max_reference_size, size))
    {
        return failure("Malformed or unsupported key-reference PEM.");
    }

    const auto der = std::as_bytes(std::span{data, static_cast<std::size_t>(size)});
    if (!is_canonical_pem(pem, der))
    {
        return failure("The key-reference PEM is not canonical.");
    }

    return impl::decode_key_reference_der(der, error);
}

std::optional<KeyReference> decode_key_reference_pem(std::string_view pem)
{
    impl::ReferenceError error{};
    return impl::decode_key_reference_pem(pem, error);
}

} // namespace mpss
