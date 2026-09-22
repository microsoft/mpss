// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/serialization.h"
#include "mpss/utils/scope_guard.h"
#include "tests/openssl_raii.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <string>
#include <string_view>

namespace
{

using namespace mpss;
using namespace mpss_openssl::testing;
using namespace std::string_view_literals;

std::string der_value(int tag, std::string_view content, bool constructed = false, int tag_class = V_ASN1_UNIVERSAL)
{
    const int size = ASN1_object_size(constructed ? 1 : 0, static_cast<int>(content.size()), tag);
    std::string result(static_cast<std::size_t>(size), '\0');
    auto *cursor = reinterpret_cast<unsigned char *>(result.data());
    ASN1_put_object(&cursor, constructed ? 1 : 0, static_cast<int>(content.size()), tag, tag_class);
    std::memcpy(cursor, content.data(), content.size());
    return result;
}

std::string public_key_der(EVP_PKEY *key)
{
    unsigned char *data = nullptr;
    const int size = i2d_PUBKEY(key, &data);
    SCOPE_GUARD(OPENSSL_free(data));
    return 0 < size ? std::string{reinterpret_cast<const char *>(data), static_cast<std::size_t>(size)} : std::string{};
}

std::string reference_der(const KeyReference &reference, EVP_PKEY *key)
{
    std::string fields = der_value(V_ASN1_INTEGER, "\1"sv) +
                         der_value(V_ASN1_UTF8STRING, reference.location.backend_name) +
                         der_value(V_ASN1_UTF8STRING, reference.location.name);
    if (reference.location.device_id)
    {
        fields +=
            der_value(0, der_value(V_ASN1_UTF8STRING, *reference.location.device_id), true, V_ASN1_CONTEXT_SPECIFIC);
    }
    return der_value(V_ASN1_SEQUENCE, fields + public_key_der(key), true);
}

void expect_same_reference(const KeyReference &expected, const KeyReference &actual)
{
    EXPECT_EQ(expected.location.backend_name, actual.location.backend_name);
    EXPECT_EQ(expected.location.name, actual.location.name);
    EXPECT_EQ(expected.location.device_id, actual.location.device_id);
    EXPECT_EQ(expected.algorithm, actual.algorithm);
    EXPECT_EQ(expected.public_key, actual.public_key);
}

class MPSSSerialization : public ::testing::TestWithParam<Algorithm>
{
  protected:
    OSSL_LIB_CTX *context = nullptr;
    OSSL_PROVIDER *provider = nullptr;
    evp_pkey_ptr key;
    KeyReference reference;

    void SetUp() override
    {
        context = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, context);
        provider = OSSL_PROVIDER_load(context, "default");
        ASSERT_NE(nullptr, provider);
        const char *group = nullptr;
        switch (GetParam())
        {
        case Algorithm::ecdsa_secp256r1_sha256:
            group = "prime256v1";
            break;
        case Algorithm::ecdsa_secp384r1_sha384:
            group = "secp384r1";
            break;
        case Algorithm::ecdsa_secp521r1_sha512:
            group = "secp521r1";
            break;
        default:
            FAIL() << "Unsupported test algorithm.";
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg) - OpenSSL API.
        key.reset(EVP_PKEY_Q_keygen(context, "provider=default", "EC", group));
        ASSERT_NE(nullptr, key);
        reference = {
            .location = {.backend_name = "unavailable-backend", .name = "offline-reference", .device_id = std::nullopt},
            .algorithm = GetParam(),
            .public_key = {}};
        const auto bits = get_algorithm_info(GetParam()).key_bits;
        reference.public_key.resize(1 + (2 * ((bits + 7) / 8)));
        std::size_t written = 0;
        ASSERT_EQ(1, EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                                     reinterpret_cast<unsigned char *>(reference.public_key.data()),
                                                     reference.public_key.size(), &written));
        ASSERT_EQ(reference.public_key.size(), written);
    }

    void TearDown() override
    {
        key.reset();
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(context);
    }
};

// NOLINTBEGIN(bugprone-throwing-static-initialization,cppcoreguidelines-owning-memory,misc-override-with-different-visibility,modernize-type-traits)
// - GoogleTest generates registration and test classes.
TEST_P(MPSSSerialization, OfflineRoundTripMatchesIndependentDer)
{
    OSSL_LIB_CTX *application_context = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, application_context);
    SCOPE_GUARD(OSSL_LIB_CTX_free(application_context));
    ASSERT_EQ(1, EVP_set_default_properties(application_context, "provider=unavailable"));
    OSSL_LIB_CTX *previous = OSSL_LIB_CTX_set0_default(application_context);
    SCOPE_GUARD(OSSL_LIB_CTX_set0_default(previous));

    for (const auto &device : {std::optional<std::string>{}, std::optional<std::string>{"12345678"}})
    {
        reference.location.device_id = device;
        const auto der = encode_key_reference_der(reference);
        ASSERT_TRUE(der.has_value()) << get_error();
        const std::string expected = reference_der(reference, key.get());
        EXPECT_TRUE(std::ranges::equal(*der, std::as_bytes(std::span{expected})));
        const auto decoded = decode_key_reference_der(*der);
        ASSERT_TRUE(decoded.has_value()) << get_error();
        expect_same_reference(reference, *decoded);

        const auto pem = encode_key_reference_pem(reference);
        ASSERT_TRUE(pem.has_value()) << get_error();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
        const auto &pem_text = pem.value();
        EXPECT_EQ(std::string::npos, pem_text.find('\r'));
        EXPECT_TRUE(pem_text.ends_with("-----END MPSS KEY REFERENCE-----\n"));
        const auto parsed = decode_key_reference_pem(" \t\r\n" + pem_text + "\r\n ");
        ASSERT_TRUE(parsed.has_value()) << get_error();
        expect_same_reference(reference, *parsed);
        EXPECT_EQ(pem, encode_key_reference_pem(*parsed));
        EXPECT_FALSE(has_error());
    }
}

TEST_P(MPSSSerialization, RejectsInvalidInputsAndClearsErrorsOnSuccess)
{
    const auto der = encode_key_reference_der(reference);
    const auto pem = encode_key_reference_pem(reference);
    ASSERT_TRUE(der.has_value());
    ASSERT_TRUE(pem.has_value());
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
    const auto &der_bytes = der.value();
    for (std::size_t size = 0; size < der_bytes.size(); ++size)
    {
        SCOPED_TRACE(size);
        EXPECT_FALSE(decode_key_reference_der(std::span{der_bytes}.first(size)));
        EXPECT_TRUE(has_error());
    }
    auto trailing = *der;
    trailing.push_back(std::byte{0});
    EXPECT_FALSE(decode_key_reference_der(trailing));
    EXPECT_FALSE(decode_key_reference_der(std::vector<std::byte>(4097)));
    for (const auto &bad : {std::string{}, std::string(8193, ' '), *pem + "junk", *pem + *pem, "junk\n" + *pem,
                            std::string{"-----BEGIN MPSS KEY REFERENCE-----\n!!!\n-----END MPSS KEY REFERENCE-----\n"},
                            std::string{"os\0name", 7}, std::string{"MPSS-REF\0\0", 10}, *pem + '\0'})
    {
        EXPECT_FALSE(decode_key_reference_pem(bad));
        EXPECT_TRUE(has_error());
    }
    for (const auto &name : {std::string{}, std::string{"line\nbreak"}, std::string(65, 'x')})
    {
        auto invalid = reference;
        invalid.location.name = name;
        EXPECT_FALSE(encode_key_reference_pem(invalid));
        EXPECT_TRUE(has_error());
    }
    auto invalid = reference;
    invalid.location.device_id = "";
    EXPECT_FALSE(encode_key_reference_der(invalid));
    invalid = reference;
    invalid.algorithm = Algorithm::unsupported;
    EXPECT_FALSE(encode_key_reference_der(invalid));
    invalid = reference;
    invalid.public_key.pop_back();
    EXPECT_FALSE(encode_key_reference_der(invalid));
    invalid = reference;
    std::fill(invalid.public_key.begin() + 1, invalid.public_key.end(), std::byte{0});
    EXPECT_FALSE(encode_key_reference_der(invalid));
    EXPECT_TRUE(has_error());
    EXPECT_EQ(pem, encode_key_reference_pem(reference));
    EXPECT_FALSE(has_error());
    EXPECT_TRUE(decode_key_reference_pem(*pem));
    EXPECT_FALSE(has_error());
}

TEST_P(MPSSSerialization, NormalizesPublicKeyAndRejectsExplicitParameters)
{
    ASSERT_EQ(1, EVP_PKEY_set_utf8_string_param(key.get(), OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED));
    const auto compressed = reference_der(reference, key.get());
    const auto decoded = decode_key_reference_der(std::as_bytes(std::span{compressed}));
    ASSERT_TRUE(decoded.has_value()) << get_error();
    expect_same_reference(reference, *decoded);
    EXPECT_EQ(encode_key_reference_der(reference), encode_key_reference_der(*decoded));

    ASSERT_EQ(1,
              EVP_PKEY_set_utf8_string_param(key.get(), OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_EC_ENCODING_EXPLICIT));
    const auto explicit_parameters = reference_der(reference, key.get());
    EXPECT_FALSE(decode_key_reference_der(std::as_bytes(std::span{explicit_parameters})));
    EXPECT_NE(std::string::npos, get_error().find("Unsupported"));
}

TEST_P(MPSSSerialization, RejectsNoncanonicalAndUnsupportedReferences)
{
    const std::string spki = public_key_der(key.get());
    const std::string location = der_value(V_ASN1_UTF8STRING, reference.location.backend_name) +
                                 der_value(V_ASN1_UTF8STRING, reference.location.name);
    const std::string fields = der_value(V_ASN1_INTEGER, "\1"sv) + location + spki;
    const std::string valid = der_value(V_ASN1_SEQUENCE, fields, true);
    const std::string device = der_value(0, der_value(V_ASN1_UTF8STRING, "123"), true, V_ASN1_CONTEXT_SPECIFIC);
    const std::string prefix = der_value(V_ASN1_INTEGER, "\1"sv) + location;
    const std::vector malformed{
        std::string{"\x30\x80", 2} + fields + std::string(2, '\0'),
        der_value(V_ASN1_SEQUENCE, der_value(V_ASN1_INTEGER, "\0\1"sv) + location + spki, true),
        der_value(V_ASN1_SEQUENCE, der_value(V_ASN1_INTEGER, "\xff"sv) + location + spki, true),
        der_value(V_ASN1_SEQUENCE, prefix + device + device + spki, true),
        der_value(V_ASN1_SEQUENCE, prefix + spki + device, true),
        der_value(V_ASN1_SEQUENCE, prefix, true),
        der_value(V_ASN1_SEQUENCE, prefix + der_value(V_ASN1_OCTET_STRING, spki), true),
        der_value(V_ASN1_SEQUENCE, prefix + spki + der_value(V_ASN1_INTEGER, "\1"sv), true),
        der_value(0, der_value(V_ASN1_SEQUENCE, der_value(V_ASN1_BOOLEAN, "\xff"sv) + location, true), true,
                  V_ASN1_CONTEXT_SPECIFIC)};
    for (const auto &bytes : malformed)
    {
        EXPECT_FALSE(decode_key_reference_der(std::as_bytes(std::span{bytes})));
        EXPECT_TRUE(has_error());
    }
    for (const auto version : {"\0"sv, "\2"sv})
    {
        auto versioned_fields = der_value(V_ASN1_INTEGER, version);
        versioned_fields.append(location).append(spki);
        const auto bytes = der_value(V_ASN1_SEQUENCE, versioned_fields, true);
        EXPECT_FALSE(decode_key_reference_der(std::as_bytes(std::span{bytes})));
        EXPECT_NE(std::string::npos, get_error().find("Unsupported key-reference version"));
    }
    const auto decoded = decode_key_reference_der(std::as_bytes(std::span{valid}));
    ASSERT_TRUE(decoded.has_value()) << get_error();
    expect_same_reference(reference, *decoded);
}

TEST(SerializationReference, RejectsNonOctetAlignedPublicKey)
{
    // The negated generator's even final octet lets a one-bit unused count preserve the point bytes.
    constexpr std::array<unsigned char, 65> point{
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0xb0,
        0x1c, 0xbd, 0x1c, 0x01, 0xe5, 0x80, 0x65, 0x71, 0x18, 0x14, 0xb5, 0x83, 0xf0, 0x61, 0xe9, 0xd4, 0x31,
        0xcc, 0xa9, 0x94, 0xce, 0xa1, 0x31, 0x34, 0x49, 0xbf, 0x97, 0xc8, 0x40, 0xae, 0x0a};
    const auto bytes = std::as_bytes(std::span{point});
    const KeyReference reference{.location = {.backend_name = "os", .name = "bit-string", .device_id = std::nullopt},
                                 .algorithm = Algorithm::ecdsa_secp256r1_sha256,
                                 .public_key = {bytes.begin(), bytes.end()}};
    const auto encoded = encode_key_reference_der(reference);
    ASSERT_TRUE(encoded.has_value()) << get_error();
    auto malformed = *encoded;
    ASSERT_GT(malformed.size(), bytes.size());
    ASSERT_TRUE(std::ranges::equal(std::span{malformed}.last(bytes.size()), bytes));
    const auto unused_bits = malformed.size() - bytes.size() - 1;
    ASSERT_EQ(std::byte{0}, malformed[unused_bits]);
    malformed[unused_bits] = std::byte{1};
    EXPECT_FALSE(decode_key_reference_der(malformed));
    EXPECT_NE(std::string::npos, get_error().find("Invalid key-reference public key"));
    EXPECT_TRUE(decode_key_reference_der(*encoded));
    EXPECT_FALSE(has_error());
}

INSTANTIATE_TEST_SUITE_P(Algorithms, MPSSSerialization,
                         ::testing::Values(Algorithm::ecdsa_secp256r1_sha256, Algorithm::ecdsa_secp384r1_sha384,
                                           Algorithm::ecdsa_secp521r1_sha512));
// NOLINTEND(bugprone-throwing-static-initialization,cppcoreguidelines-owning-memory,misc-override-with-different-visibility,modernize-type-traits)

} // namespace
