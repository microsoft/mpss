// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/serialization.h"
#include "mpss/mpss.h"
#include "mpss/serialization.h"
#include "mpss/utils/scope_guard.h"
#include "tests/openssl_raii.h"
#include "tests/reference_der.h"
#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using namespace mpss;
using namespace mpss::tests;
using namespace mpss_openssl::tests;
using namespace std::string_view_literals;
using mpss::impl::ReferenceError;
using mpss::utils::fn_deleter;

using bignum_ptr = std::unique_ptr<BIGNUM, fn_deleter<BN_free>>;
using ec_group_ptr = std::unique_ptr<EC_GROUP, fn_deleter<EC_GROUP_free>>;
using ec_point_ptr = std::unique_ptr<EC_POINT, fn_deleter<EC_POINT_free>>;

constexpr std::string_view pem_label = "MPSS KEY REFERENCE";
constexpr std::string_view pem_end_line = "-----END MPSS KEY REFERENCE-----";
constexpr std::string_view base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

[[nodiscard]]
std::optional<KeyReference> decode(std::string_view der)
{
    return decode_key_reference_der(std::as_bytes(std::span{der}));
}

// The failure category reported by the structured entry point, or nullopt when decoding succeeds.
// Decoded twice from opposite starting values: a category the decoder never wrote shows up as a
// disagreement between the two, rather than as whichever value the variable happened to start with.
[[nodiscard]]
std::optional<ReferenceError> decode_error(std::string_view der)
{
    ReferenceError from_malformed = ReferenceError::malformed;
    const std::optional<KeyReference> malformed_run =
        impl::decode_key_reference_der(std::as_bytes(std::span{der}), from_malformed);

    ReferenceError from_unsupported = ReferenceError::unsupported;
    const std::optional<KeyReference> unsupported_run =
        impl::decode_key_reference_der(std::as_bytes(std::span{der}), from_unsupported);

    EXPECT_EQ(malformed_run.has_value(), unsupported_run.has_value()) << "decoding the same input twice disagreed";
    if (malformed_run)
    {
        return std::nullopt;
    }

    EXPECT_EQ(from_malformed, from_unsupported) << "the decoder did not report a failure category";
    return from_malformed;
}

void expect_same_reference(const KeyReference &expected, const std::optional<KeyReference> &actual)
{
    ASSERT_TRUE(actual.has_value()) << get_error();
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
    const auto &value = actual.value();
    EXPECT_EQ(expected.location.backend_name, value.location.backend_name);
    EXPECT_EQ(expected.location.name, value.location.name);
    EXPECT_EQ(expected.location.device_id, value.location.device_id);
    EXPECT_EQ(expected.algorithm, value.algorithm);
    EXPECT_EQ(expected.public_key, value.public_key);
}

// Lengthens the name until the Base64 body ends with padding, whose unused bits the tests vary.
[[nodiscard]]
std::string padded_pem(KeyReference reference)
{
    for (;;)
    {
        const auto pem = encode_key_reference_pem(reference);
        if (!pem)
        {
            return {};
        }

        if (std::string::npos != pem->find('='))
        {
            return *pem;
        }

        reference.location.name.push_back('x');
    }
}

class MPSSSerialization : public ::testing::TestWithParam<Algorithm>
{
  protected:
    OSSL_LIB_CTX *context = nullptr;
    OSSL_PROVIDER *provider = nullptr;
    int group_nid = NID_undef;
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

        group_nid = OBJ_sn2nid(group);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg) - OpenSSL API.
        key.reset(EVP_PKEY_Q_keygen(context, "provider=default", "EC", group));
        ASSERT_NE(nullptr, key);

        // An unavailable backend demonstrates that serialization never resolves the stored location.
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

    [[nodiscard]]
    std::string point() const
    {
        return {reinterpret_cast<const char *>(reference.public_key.data()), reference.public_key.size()};
    }

    // An uncompressed point of the group whose x coordinate is written as x + p: the same point once reduced,
    // but not a valid field-element encoding.
    [[nodiscard]]
    std::string unreduced_point() const
    {
        const ec_group_ptr group(EC_GROUP_new_by_curve_name(group_nid));
        const ec_point_ptr point(EC_POINT_new(group.get()));
        const bignum_ptr x(BN_new());
        const bignum_ptr p(BN_new());
        if (!group || !point || !x || !p || 1 != EC_GROUP_get_curve(group.get(), p.get(), nullptr, nullptr, nullptr))
        {
            return {};
        }

        // Half of all x coordinates have a point; the first few candidates suffice.
        bool found = false;
        for (unsigned long candidate = 0; !found && 64 > candidate; ++candidate)
        {
            found = 1 == BN_set_word(x.get(), candidate) &&
                    1 == EC_POINT_set_compressed_coordinates(group.get(), point.get(), x.get(), 0, nullptr);
        }

        std::string encoded(reference.public_key.size(), '\0');
        const std::size_t field_size = (encoded.size() - 1) / 2;
        auto *data = reinterpret_cast<unsigned char *>(encoded.data());
        if (!found ||
            encoded.size() != EC_POINT_point2oct(group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED, data,
                                                 encoded.size(), nullptr) ||
            1 != BN_add(x.get(), x.get(), p.get()) ||
            static_cast<int>(field_size) != BN_bn2binpad(x.get(), data + 1, static_cast<int>(field_size)))
        {
            return {};
        }

        return encoded;
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
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
        const auto &der_bytes = der.value();
        const std::string expected = reference_der(reference, key.get());
        EXPECT_TRUE(std::ranges::equal(der_bytes, std::as_bytes(std::span{expected})));
        expect_same_reference(reference, decode_key_reference_der(der_bytes));

        const auto pem = encode_key_reference_pem(reference);
        ASSERT_TRUE(pem.has_value()) << get_error();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
        const auto &pem_text = pem.value();
        EXPECT_EQ(std::string::npos, pem_text.find('\r'));
        EXPECT_TRUE(pem_text.ends_with(std::string{pem_end_line} + '\n'));
        expect_same_reference(reference, decode_key_reference_pem(" \t\r\n" + pem_text + "\r\n "));
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
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
    const auto &pem_text = pem.value();

    // DER framing must reject every truncation, excess data, and oversized input as malformed.
    const std::string_view der_text{reinterpret_cast<const char *>(der_bytes.data()), der_bytes.size()};
    for (std::size_t size = 0; size < der_text.size(); ++size)
    {
        SCOPED_TRACE(size);
        EXPECT_EQ(ReferenceError::malformed, decode_error(der_text.substr(0, size)));
        EXPECT_TRUE(has_error());
    }

    EXPECT_EQ(ReferenceError::malformed, decode_error(std::string{der_text} + '\0'));
    EXPECT_EQ(ReferenceError::malformed, decode_error(std::string(4097, '\0')));

    // The PEM entry point accepts exactly one reference document, not arbitrary surrounding text.
    for (const auto &bad :
         {std::string{}, std::string(8193, ' '), pem_text + "junk", pem_text + pem_text, "junk\n" + pem_text,
          std::string{"-----BEGIN MPSS KEY REFERENCE-----\n!!!\n-----END MPSS KEY REFERENCE-----\n"},
          std::string{"os\0name", 7}, std::string{"MPSS-REF\0\0", 10}, pem_text + '\0'})
    {
        EXPECT_FALSE(decode_key_reference_pem(bad));
        EXPECT_TRUE(has_error());
    }

    // Encoding rejects invalid caller-owned fields, not just malformed serialized input.
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

    // Successful operations clear a preceding failure rather than leaking stale diagnostics.
    EXPECT_EQ(pem, encode_key_reference_pem(reference));
    EXPECT_FALSE(has_error());
    EXPECT_TRUE(decode_key_reference_pem(pem_text));
    EXPECT_FALSE(has_error());
}

TEST_P(MPSSSerialization, AcceptsOnlyCanonicalPemText)
{
    const std::string pem = padded_pem(reference);
    ASSERT_FALSE(pem.empty()) << get_error();
    const auto begin_end = pem.find('\n');
    const auto end_line = pem.rfind(pem_end_line);
    const auto pad = pem.find('=');
    ASSERT_NE(std::string::npos, begin_end);
    ASSERT_NE(std::string::npos, end_line);
    ASSERT_NE(std::string::npos, pad);
    const std::string begin = pem.substr(0, begin_end + 1);
    const std::string body = pem.substr(begin_end + 1, end_line - begin_end - 1);
    const std::string end = pem.substr(end_line);

    std::string indented;
    std::string joined;
    for (std::size_t start = 0; start < body.size();)
    {
        const auto stop = body.find('\n', start);
        const std::string line = body.substr(start, stop - start);
        indented += "  " + line + "\n";
        joined += line + (joined.size() % 2 ? " " : "\t");
        start = stop + 1;
    }

    joined.back() = '\n';
    auto trailing_bits = pem;
    trailing_bits[pad - 1] = base64_alphabet[base64_alphabet.find(pem[pad - 1]) ^ 1U];
    auto control = pem;
    control.insert(pem.find('\n', begin_end + 1), "\x01");
    auto lowercase = pem;
    for (auto at = lowercase.find(pem_label); std::string::npos != at; at = lowercase.find(pem_label, at + 1))
    {
        lowercase.replace(at, pem_label.size(), "mpss key reference");
    }

    // Base64 decoding stops at '-', treats control bytes as whitespace, and ignores unused trailing bits;
    // PEM reading accepts headers and stray line text. Only the canonical text is a key reference.
    for (const auto &rejected :
         {begin + body + "-AAAA\n" + end, begin + "\n" + body + end, begin + indented + end, begin + joined + end,
          control, trailing_bits, pem.substr(0, pem.size() - 1) + "ignored\n", "\xEF\xBB\xBF" + pem, lowercase,
          pem.substr(0, begin_end) + " " + pem.substr(begin_end), begin + "Proc-Type: 4,ENCRYPTED\n\n" + body + end,
          std::string(8193 - pem.size(), ' ') + pem})
    {
        EXPECT_FALSE(decode_key_reference_pem(rejected));
        EXPECT_TRUE(has_error());
    }

    std::string crlf;
    for (const char c : pem)
    {
        if ('\n' == c)
        {
            crlf.push_back('\r');
        }

        crlf.push_back(c);
    }

    for (const auto &accepted : {crlf, std::string(8192 - pem.size(), ' ') + pem})
    {
        EXPECT_TRUE(decode_key_reference_pem(accepted)) << get_error();
        EXPECT_FALSE(has_error());
    }
}

TEST_P(MPSSSerialization, NormalizesPublicKeyAndRejectsExplicitParameters)
{
    // Compressed and hybrid points denote the same key and decode to the uncompressed public bytes.
    for (const char *format :
         {OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID})
    {
        ASSERT_EQ(1, EVP_PKEY_set_utf8_string_param(key.get(), OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, format));
        const std::string encoded = reference_der(reference, key.get());
        ASSERT_EQ(std::string::npos, encoded.find(point()));
        expect_same_reference(reference, decode(encoded));
    }

    ASSERT_EQ(1,
              EVP_PKEY_set_utf8_string_param(key.get(), OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_EC_ENCODING_EXPLICIT));
    EXPECT_EQ(ReferenceError::unsupported, decode_error(reference_der(reference, key.get())));
    EXPECT_NE(std::string::npos, get_error().find("Unsupported key-reference public-key algorithm"));
}

TEST_P(MPSSSerialization, RejectsNoncanonicalAndUnsupportedReferences)
{
    const std::string spki = public_key_der(key.get());
    const std::string location = der_value(V_ASN1_UTF8STRING, reference.location.backend_name) +
                                 der_value(V_ASN1_UTF8STRING, reference.location.name);
    const std::string prefix = der_value(V_ASN1_INTEGER, "\1"sv) + location;
    const std::string fields = prefix + spki;
    const std::string valid = der_value(V_ASN1_SEQUENCE, fields, true);
    const std::string device = der_value(0, der_value(V_ASN1_UTF8STRING, "123"), true, V_ASN1_CONTEXT_SPECIFIC);
    ASSERT_GT(0x10000U, fields.size());
    const std::string long_length{static_cast<char>(fields.size() >> 8U), static_cast<char>(fields.size() & 0xffU)};

    // OpenSSL decodes these BER forms, so only the re-encoding comparison rejects them.
    for (const auto &noncanonical :
         {std::string{"\x30\x80", 2} + fields + std::string(2, '\0'), std::string{"\x30\x82", 2} + long_length + fields,
          std::string{"\x3f\x10", 2} + valid.substr(1)})
    {
        EXPECT_EQ(ReferenceError::malformed, decode_error(noncanonical));
        EXPECT_NE(std::string::npos, get_error().find("not canonical DER"));
    }

    const std::vector malformed{
        der_value(V_ASN1_SEQUENCE, der_value(V_ASN1_INTEGER, "\0\1"sv) + location + spki, true),
        der_value(V_ASN1_SEQUENCE, prefix + device + device + spki, true),
        der_value(V_ASN1_SEQUENCE, prefix + spki + device, true),
        der_value(V_ASN1_SEQUENCE, prefix + std::string{"\x80\x01\x31", 3} + spki, true),
        der_value(V_ASN1_SEQUENCE, prefix, true),
        der_value(V_ASN1_SEQUENCE, prefix + der_value(V_ASN1_OCTET_STRING, spki), true),
        der_value(V_ASN1_SEQUENCE, prefix + spki + der_value(V_ASN1_INTEGER, "\1"sv), true),
        der_value(0, der_value(V_ASN1_SEQUENCE, der_value(V_ASN1_BOOLEAN, "\xff"sv) + location, true), true,
                  V_ASN1_CONTEXT_SPECIFIC)};

    for (const auto &bytes : malformed)
    {
        EXPECT_EQ(ReferenceError::malformed, decode_error(bytes));
        EXPECT_TRUE(has_error());
    }

    // A negative version is malformed; other unknown versions, including one beyond 64 bits, are unsupported.
    EXPECT_EQ(ReferenceError::malformed,
              decode_error(der_value(V_ASN1_SEQUENCE, der_value(V_ASN1_INTEGER, "\xff"sv) + location + spki, true)));
    EXPECT_NE(std::string::npos, get_error().find("Invalid key-reference version"));
    for (const auto version : {"\0"sv, "\2"sv, "\1\0\0\0\0\0\0\0\0"sv})
    {
        EXPECT_EQ(ReferenceError::unsupported,
                  decode_error(der_value(V_ASN1_SEQUENCE, der_value(V_ASN1_INTEGER, version) + location + spki, true)));
        EXPECT_NE(std::string::npos, get_error().find("Unsupported key-reference version"));
    }

    expect_same_reference(reference, decode(valid));
}

TEST_P(MPSSSerialization, RejectsInvalidPublicKeys)
{
    ASSERT_EQ(public_key_der(key.get()), spki_der(ec_algorithm(group_nid), point()));
    std::string off_group = point();
    off_group.back() ^= 1;
    const std::string unreduced = unreduced_point();
    ASSERT_FALSE(unreduced.empty());

    for (const auto &invalid : {off_group, unreduced, std::string{"\0", 1}, std::string{}})
    {
        EXPECT_EQ(ReferenceError::malformed,
                  decode_error(reference_der(reference, spki_der(ec_algorithm(group_nid), invalid))));
        EXPECT_NE(std::string::npos, get_error().find("Invalid key-reference public key"));
    }
}

TEST_P(MPSSSerialization, BoundsLocationText)
{
    // The decoder holds serialized text to the same bounded printable ASCII as the encoder.
    auto invalid = reference;
    for (const auto &name :
         {std::string{"nul\0byte", 8}, std::string{"\xc3\xa9"}, std::string{"\x7f"}, std::string(65, 'n')})
    {
        invalid.location.name = name;
        EXPECT_EQ(ReferenceError::malformed, decode_error(reference_der(invalid, key.get())));
        EXPECT_NE(std::string::npos, get_error().find("Invalid key-reference location"));
    }

    invalid = reference;
    invalid.location.backend_name = std::string(65, 'b');
    EXPECT_EQ(ReferenceError::malformed, decode_error(reference_der(invalid, key.get())));
    invalid = reference;
    invalid.location.device_id = std::string(257, 'd');
    EXPECT_EQ(ReferenceError::malformed, decode_error(reference_der(invalid, key.get())));

    std::string printable;
    for (char c = 0x20; 0x7e >= c; ++c)
    {
        printable.push_back(c);
    }

    auto bounded = reference;
    bounded.location.backend_name = printable.substr(64);
    bounded.location.name = printable.substr(0, 64);
    bounded.location.device_id = std::string(256 - printable.size(), '~') + printable;
    const auto der = encode_key_reference_der(bounded);
    ASSERT_TRUE(der.has_value()) << get_error();
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
    const auto &der_bytes = der.value();
    const std::string expected = reference_der(bounded, key.get());
    EXPECT_TRUE(std::ranges::equal(der_bytes, std::as_bytes(std::span{expected})));
    expect_same_reference(bounded, decode_key_reference_der(der_bytes));
    expect_same_reference(bounded, decode_key_reference_pem(encode_key_reference_pem(bounded).value_or("")));
}

TEST(MPSSSerialization, RejectsForeignPublicKeyAlgorithms)
{
    const KeyReference reference{.location = {.backend_name = "os", .name = "foreign", .device_id = std::nullopt},
                                 .algorithm = Algorithm::unsupported,
                                 .public_key = {}};
    const std::string public_key(65, 'p');
    for (const auto &algorithm :
         {oid_der(NID_rsaEncryption) + der_value(V_ASN1_NULL, {}), oid_der(NID_ED25519), ec_algorithm(NID_secp256k1)})
    {
        EXPECT_EQ(ReferenceError::unsupported, decode_error(reference_der(reference, spki_der(algorithm, public_key))));
        EXPECT_NE(std::string::npos, get_error().find("Unsupported key-reference public-key algorithm"));
    }
}

TEST(MPSSSerialization, RejectsNonOctetAlignedPublicKey)
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
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
    const auto &encoded_bytes = encoded.value();

    // Locate the final BIT STRING by checking its bytes, then change only its declared unused-bit count.
    auto malformed = encoded_bytes;
    ASSERT_GT(malformed.size(), bytes.size());
    ASSERT_TRUE(std::ranges::equal(std::span{malformed}.last(bytes.size()), bytes));
    const auto unused_bits = malformed.size() - bytes.size() - 1;
    ASSERT_EQ(std::byte{0}, malformed[unused_bits]);
    malformed[unused_bits] = std::byte{1};
    EXPECT_FALSE(decode_key_reference_der(malformed));
    EXPECT_NE(std::string::npos, get_error().find("Invalid key-reference public key"));

    EXPECT_TRUE(decode_key_reference_der(encoded_bytes));
    EXPECT_FALSE(has_error());
}

// A reference recorded once and checked byte for byte ever after. The round-trip tests prove the
// encoder and decoder agree with each other; this proves they still agree with what MPSS already
// wrote, which is what a stored reference from an older build depends on. The point is the P-256
// generator, so the vector can be rebuilt from published values rather than from this code.
TEST(MPSSSerialization, MatchesTheRecordedWireFormat)
{
    constexpr std::string_view golden_pem = "-----BEGIN MPSS KEY REFERENCE-----\n"
                                            "MIGCAgEBDAd5dWJpa2V5DA1nb2xkZW4tdmVjdG9yoAoMCDEyMzQ1Njc4MFkwEwYH\n"
                                            "KoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5\n"
                                            "RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n"
                                            "-----END MPSS KEY REFERENCE-----\n";

    // SEQUENCE { INTEGER 1, UTF8String "yubikey", UTF8String "golden-vector",
    //            [0] { UTF8String "12345678" }, SubjectPublicKeyInfo }
    constexpr std::array<unsigned char, 133> golden_der{
        0x30, 0x81, 0x82, 0x02, 0x01, 0x01, 0x0c, 0x07, 0x79, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x0c, 0x0d,
        0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x2d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0xa0, 0x0a, 0x0c, 0x08,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f,
        0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce,
        0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

    constexpr std::array<unsigned char, 65> generator{
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f,
        0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce,
        0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
    const auto generator_bytes = std::as_bytes(std::span{generator});

    const KeyReference expected{
        .location = {.backend_name = "yubikey", .name = "golden-vector", .device_id = std::string{"12345678"}},
        .algorithm = Algorithm::ecdsa_secp256r1_sha256,
        .public_key = {generator_bytes.begin(), generator_bytes.end()}};

    // What is stored still reads back as what was stored.
    expect_same_reference(expected, decode_key_reference_pem(golden_pem));
    expect_same_reference(expected, decode_key_reference_der(std::as_bytes(std::span{golden_der})));

    // And what MPSS writes today is still byte for byte what was stored.
    const auto der = encode_key_reference_der(expected);
    ASSERT_TRUE(der.has_value()) << get_error();
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
    EXPECT_TRUE(std::ranges::equal(der.value(), std::as_bytes(std::span{golden_der})));

    const auto pem = encode_key_reference_pem(expected);
    ASSERT_TRUE(pem.has_value()) << get_error();
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - Checked by ASSERT_TRUE above.
    EXPECT_EQ(golden_pem, pem.value());
    EXPECT_FALSE(has_error());
}

INSTANTIATE_TEST_SUITE_P(Algorithms, MPSSSerialization,
                         ::testing::Values(Algorithm::ecdsa_secp256r1_sha256, Algorithm::ecdsa_secp384r1_sha384,
                                           Algorithm::ecdsa_secp521r1_sha512));
// NOLINTEND(bugprone-throwing-static-initialization,cppcoreguidelines-owning-memory,misc-override-with-different-visibility,modernize-type-traits)

} // namespace
