// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "mpss-openssl/interaction_handler.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss/interaction_handler.h"
#include "mpss/key_policy.h"
#include "mpss/mpss.h"
#include "mpss/serialization.h"
#include "mpss/utils/scope_guard.h"
#include "tests/openssl_raii.h"
#include "tests/scoped_env.h"
#include "tests/test_key_names.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <numeric>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::string_view_literals;

namespace
{

[[nodiscard]]
bool has_algorithm_name(const char *algorithm_names, std::string_view expected)
{
    if (nullptr == algorithm_names)
    {
        return false;
    }

    std::string_view remaining{algorithm_names};
    while (!remaining.empty())
    {
        const std::size_t separator = remaining.find(':');
        if (remaining.substr(0, separator) == expected)
        {
            return true;
        }
        if (std::string_view::npos == separator)
        {
            break;
        }
        remaining.remove_prefix(separator + 1);
    }

    return false;
}

class MPSSDigest : public ::testing::Test
{
  protected:
    OSSL_LIB_CTX *mpss_libctx = nullptr;
    OSSL_PROVIDER *mpss_prov = nullptr;
    OSSL_PROVIDER *default_prov = nullptr;

    void SetUp() override
    {
        mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);

        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
        mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);
        default_prov = OSSL_PROVIDER_load(mpss_libctx, "default");
        ASSERT_NE(nullptr, default_prov);
    }

    void TearDown() override
    {
        if (nullptr != mpss_prov)
        {
            ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
            mpss_prov = nullptr;
        }
        if (nullptr != default_prov)
        {
            ASSERT_NE(0, OSSL_PROVIDER_unload(default_prov));
            default_prov = nullptr;
        }
        if (nullptr != mpss_libctx)
        {
            OSSL_LIB_CTX_free(mpss_libctx);
            mpss_libctx = nullptr;
        }
    }

    void TestDigest(const char *hash_name, const EVP_MD *(*evp_md_func)(), std::string_view in)
    {
        unsigned char mpss_digest[EVP_MAX_MD_SIZE];
        unsigned char default_digest[EVP_MAX_MD_SIZE];
        unsigned int mpss_digest_len = 0;
        unsigned int default_digest_len = 0;

        EVP_MD *md = EVP_MD_fetch(mpss_libctx, hash_name, "provider=mpss");
        ASSERT_NE(nullptr, md);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, mdctx);
        ASSERT_EQ(1, EVP_DigestInit(mdctx, md));
        ASSERT_EQ(1, EVP_DigestUpdate(mdctx, in.data(), in.size()));
        unsigned int digest_len = 0;
        ASSERT_EQ(1, EVP_DigestFinal(mdctx, mpss_digest, &digest_len));
        mpss_digest_len = digest_len;
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);

        const EVP_MD *default_md = evp_md_func();
        ASSERT_NE(nullptr, default_md);
        mdctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, mdctx);
        ASSERT_EQ(1, EVP_DigestInit(mdctx, default_md));
        ASSERT_EQ(1, EVP_DigestUpdate(mdctx, in.data(), in.size()));
        ASSERT_EQ(1, EVP_DigestFinal(mdctx, default_digest, &default_digest_len));
        EVP_MD_CTX_free(mdctx);

        ASSERT_EQ(mpss_digest_len, default_digest_len);
        ASSERT_TRUE(
            std::ranges::equal(std::span{mpss_digest, mpss_digest_len}, std::span{default_digest, default_digest_len}));
    }
};

constexpr const char *mpss_p256_algorithm = "ecdsa_secp256r1_sha256";

using mpss_openssl::tests::bio_ptr;
using mpss_openssl::tests::encoder_ctx_ptr;
using mpss_openssl::tests::evp_md_ctx_ptr;
using mpss_openssl::tests::evp_pkey_ctx_ptr;
using mpss_openssl::tests::evp_pkey_ptr;
using mpss_openssl::tests::ssl_ctx_ptr;
using mpss_openssl::tests::ssl_ptr;
using mpss_openssl::tests::x509_ptr;

// Process-unique, like every other key name in this suite, so that two test binaries running at the
// same time cannot delete each other's fixture key. A function rather than a namespace-scope string
// to keep it out of static initialization and destruction.
std::string reference_fixture_key_name()
{
    return mpss::tests::test_key_name("mpss_reference_pem_fixture");
}

std::string Base64(std::string_view raw)
{
    bio_ptr sink(BIO_new(BIO_s_mem()));
    bio_ptr encoder(BIO_new(BIO_f_base64()));
    if (nullptr == sink || nullptr == encoder)
    {
        return {};
    }

    BIO_set_flags(encoder.get(), BIO_FLAGS_BASE64_NO_NL);
    const bio_ptr chain(BIO_push(encoder.release(), sink.release()));

    if (static_cast<int>(raw.size()) != BIO_write(chain.get(), raw.data(), static_cast<int>(raw.size())) ||
        1 != BIO_flush(chain.get()))
    {
        return {};
    }

    BUF_MEM *mem = nullptr;
    BIO_get_mem_ptr(chain.get(), &mem);
    if (nullptr == mem || 0 == mem->length)
    {
        return {};
    }
    return {mem->data, mem->length};
}

std::string ReferencePem(std::string_view base64_body)
{
    return "-----BEGIN MPSS KEY REFERENCE-----\n" + std::string(base64_body) + "\n-----END MPSS KEY REFERENCE-----\n";
}

std::string LegacyReferencePemFor(std::string_view backend, std::string_view key_name)
{
    std::string body(backend);
    body.push_back('\0');
    body.append(key_name);
    return ReferencePem(Base64(body));
}

std::string PublicKeyDer(EVP_PKEY *key)
{
    unsigned char *der = nullptr;
    const int size = i2d_PUBKEY(key, &der);
    SCOPE_GUARD(OPENSSL_free(der));
    return 0 < size ? std::string{reinterpret_cast<const char *>(der), static_cast<std::size_t>(size)} : std::string{};
}

// Construct fixtures with OpenSSL's generic DER writer, independently of the provider's schema.
std::string DerValue(int tag, std::string_view content, bool constructed = false, int tag_class = V_ASN1_UNIVERSAL)
{
    const int size = ASN1_object_size(constructed ? 1 : 0, static_cast<int>(content.size()), tag);
    if (0 >= size)
    {
        return {};
    }
    std::string encoded(static_cast<std::size_t>(size), '\0');
    auto *cursor = reinterpret_cast<unsigned char *>(encoded.data());
    ASN1_put_object(&cursor, constructed ? 1 : 0, static_cast<int>(content.size()), tag, tag_class);
    std::memcpy(cursor, content.data(), content.size());
    return encoded;
}

std::string DerInteger(std::int64_t value)
{
    ASN1_INTEGER *integer = ASN1_INTEGER_new();
    if (nullptr == integer)
    {
        return {};
    }
    SCOPE_GUARD(ASN1_INTEGER_free(integer));
    if (1 != ASN1_INTEGER_set_int64(integer, value))
    {
        return {};
    }
    unsigned char *der = nullptr;
    const int size = i2d_ASN1_INTEGER(integer, &der);
    SCOPE_GUARD(OPENSSL_free(der));
    return 0 < size ? std::string{reinterpret_cast<const char *>(der), static_cast<std::size_t>(size)} : std::string{};
}

std::string BoundReference(std::string_view backend, std::string_view name, std::string_view device,
                           std::string_view spki, std::int64_t version = 1)
{
    std::string body = DerInteger(version) + DerValue(V_ASN1_UTF8STRING, backend) + DerValue(V_ASN1_UTF8STRING, name);
    if (!device.empty())
    {
        body += DerValue(0, DerValue(V_ASN1_UTF8STRING, device), true, V_ASN1_CONTEXT_SPECIFIC);
    }
    body += spki;
    return DerValue(V_ASN1_SEQUENCE, body, true);
}

std::string InternalLocatorReference(std::string_view backend, std::string_view name, bool use_defaults)
{
    const std::string body = DerValue(V_ASN1_BOOLEAN, use_defaults ? "\xff"sv : "\0"sv) +
                             DerValue(V_ASN1_UTF8STRING, backend) + DerValue(V_ASN1_UTF8STRING, name);
    return DerValue(0, DerValue(V_ASN1_SEQUENCE, body, true), true, V_ASN1_CONTEXT_SPECIFIC);
}

std::string ReferenceBody(const std::string &pem)
{
    const bio_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    char *name = nullptr;
    char *header = nullptr;
    unsigned char *body = nullptr;
    long size = 0;
    SCOPE_GUARD(OPENSSL_free(name));
    SCOPE_GUARD(OPENSSL_free(header));
    SCOPE_GUARD(OPENSSL_free(body));
    if (!bio || 1 != PEM_read_bio(bio.get(), &name, &header, &body, &size) || 0 >= size)
    {
        return {};
    }
    return {reinterpret_cast<const char *>(body), static_cast<std::size_t>(size)};
}

evp_pkey_ptr GenerateKey(OSSL_LIB_CTX *libctx, const std::string &key_name, const char *backend = nullptr,
                         std::uint64_t key_policy = MPSS_KEY_POLICY_NONE, const char *device_id = nullptr)
{
    evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss"));
    if (nullptr == ctx || 1 != EVP_PKEY_keygen_init(ctx.get()))
    {
        return nullptr;
    }

    OSSL_PARAM params[6];
    int count = 0;
    params[count++] = OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0);
    params[count++] = OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(mpss_p256_algorithm), 0);
    if (nullptr != backend)
    {
        params[count++] = OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(backend), 0);
    }
    if (MPSS_KEY_POLICY_NONE != key_policy)
    {
        params[count++] = OSSL_PARAM_construct_uint64("mpss_key_policy", &key_policy);
    }
    if (nullptr != device_id)
    {
        params[count++] = OSSL_PARAM_construct_utf8_string("mpss_device_id", const_cast<char *>(device_id), 0);
    }
    params[count] = OSSL_PARAM_END;
    if (1 != EVP_PKEY_CTX_set_params(ctx.get(), params))
    {
        return nullptr;
    }

    EVP_PKEY *pkey = nullptr;
    if (1 != EVP_PKEY_generate(ctx.get(), &pkey))
    {
        return nullptr;
    }
    return evp_pkey_ptr(pkey);
}

evp_pkey_ptr DecodeReferencePem(OSSL_LIB_CTX *libctx, const std::string &pem)
{
    bio_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (nullptr == bio)
    {
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey_ex(bio.get(), nullptr, nullptr, nullptr, libctx, "provider=mpss");
    return evp_pkey_ptr(pkey);
}

// Capture the provider's reference object without opening the named key or accessing a device.
int DecodeReferenceObject(OSSL_LIB_CTX *libctx, BIO *input, std::string &reference)
{
    OSSL_DECODER *decoder = OSSL_DECODER_fetch(libctx, "EC", "provider=mpss,input=pem");
    if (nullptr == decoder)
    {
        return 0;
    }
    SCOPE_GUARD(OSSL_DECODER_free(decoder));

    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new();
    if (nullptr == ctx)
    {
        return 0;
    }
    SCOPE_GUARD(OSSL_DECODER_CTX_free(ctx));

    if (1 != OSSL_DECODER_CTX_set_input_type(ctx, "PEM") ||
        1 != OSSL_DECODER_CTX_set_selection(ctx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ||
        1 != OSSL_DECODER_CTX_add_decoder(ctx, decoder) || 1 != OSSL_DECODER_CTX_set_construct_data(ctx, &reference) ||
        1 != OSSL_DECODER_CTX_set_construct(
                 ctx, [](OSSL_DECODER_INSTANCE *, const OSSL_PARAM params[], void *data) -> int {
                     const OSSL_PARAM *value = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
                     if (nullptr == value || OSSL_PARAM_OCTET_STRING != value->data_type || nullptr == value->data)
                     {
                         return 0;
                     }
                     static_cast<std::string *>(data)->assign(static_cast<const char *>(value->data), value->data_size);
                     return 1;
                 }))
    {
        return 0;
    }
    return OSSL_DECODER_from_bio(ctx, input);
}

evp_pkey_ptr GenerateFramingKey(OSSL_LIB_CTX *libctx)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg) - OpenSSL's keygen helper takes an algorithm-specific argument.
    return evp_pkey_ptr{EVP_PKEY_Q_keygen(libctx, "provider=default", "EC", SN_X9_62_prime256v1)};
}

std::string EncodeReferencePem(EVP_PKEY *key, int selection = EVP_PKEY_PRIVATE_KEY)
{
    encoder_ctx_ptr encoder(OSSL_ENCODER_CTX_new_for_pkey(key, selection, "PEM", "MpssKeyReference", "provider=mpss"));
    // The encoder count is not a usable signal: OpenSSL collects candidates before filtering by
    // structure, so it is non-zero even for a selection nothing can encode. Whether this key can be
    // encoded is decided by OSSL_ENCODER_to_bio below.
    if (nullptr == encoder)
    {
        return {};
    }

    bio_ptr bio(BIO_new(BIO_s_mem()));
    if (nullptr == bio || 1 != OSSL_ENCODER_to_bio(encoder.get(), bio.get()))
    {
        return {};
    }

    char *data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    if (0 >= size || nullptr == data)
    {
        return {};
    }
    return {data, static_cast<std::size_t>(size)};
}

std::vector<unsigned char> SignDigest(OSSL_LIB_CTX *libctx, EVP_PKEY *key)
{
    constexpr std::array<unsigned char, 32> digest{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                                   0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                                   0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=mpss"));
    if (nullptr == ctx || 1 != EVP_PKEY_sign_init(ctx.get()))
    {
        return {};
    }

    std::size_t sig_len = 0;
    if (1 != EVP_PKEY_sign(ctx.get(), nullptr, &sig_len, digest.data(), digest.size()) || 0 == sig_len)
    {
        return {};
    }

    std::vector<unsigned char> signature(sig_len);
    if (1 != EVP_PKEY_sign(ctx.get(), signature.data(), &sig_len, digest.data(), digest.size()))
    {
        return {};
    }
    signature.resize(sig_len);
    return signature;
}

// Count actual reads even if the decoder framework later restores the stream position.
void CountConsumedBytes(BIO *bio, std::size_t &consumed)
{
    BIO_set_callback_arg(bio, reinterpret_cast<char *>(&consumed));
    BIO_set_callback_ex(bio,
                        // NOLINTNEXTLINE(readability-non-const-parameter) - OpenSSL requires this callback signature.
                        [](BIO *callback_bio, int operation, const char *, std::size_t, int, long, int result,
                           std::size_t *processed) -> long {
                            if ((BIO_CB_READ | BIO_CB_RETURN) == operation && 0 < result && nullptr != processed)
                            {
                                *reinterpret_cast<std::size_t *>(BIO_get_callback_arg(callback_bio)) += *processed;
                            }
                            return result;
                        });
}

} // namespace

namespace mpss_openssl::tests
{
using mpss::tests::test_key_name;

#ifdef MPSS_BACKEND_YUBIKEY
TEST(InteractionContextTest, CCallbacksReceiveTargetAndUserData)
{
    struct Observations
    {
        int requests{0};
        int results{0};
        int touches{0};
        int completions{0};
    } observations;

    const auto previous = mpss::GetInteractionHandler();
    SCOPE_GUARD(mpss::GetOrSetInteractionHandler(previous));

    const auto check_target = [](const mpss_interaction_context_t *target) {
        EXPECT_STREQ("yubikey", target->backend_name);
        EXPECT_STREQ("35489220", target->device_id);
        EXPECT_STREQ("my-key", target->key_name);
        EXPECT_STREQ("reader", target->reader_name);
    };
    struct CallbackState
    {
        Observations *observed;
        decltype(check_target) check;
    } state{&observations, check_target};

    mpss_set_interaction_handler(
        [](const mpss_interaction_context_t *target, const char *operation, int status, int retries, char *pin,
           size_t size, void *data) {
            auto &callback = *static_cast<CallbackState *>(data);
            callback.check(target);
            ++callback.observed->requests;
            EXPECT_STREQ("sign", operation);
            EXPECT_EQ(MPSS_PIN_STATUS_FIRST_ATTEMPT, status);
            EXPECT_EQ(3, retries);
            EXPECT_EQ(MPSS_PIN_BUF_SIZE, size);
            std::memcpy(pin, "unused-test-pin", sizeof("unused-test-pin"));
            return true;
        },
        [](const mpss_interaction_context_t *target, int result, int retries, void *data) {
            auto &callback = *static_cast<CallbackState *>(data);
            callback.check(target);
            ++callback.observed->results;
            EXPECT_EQ(MPSS_PIN_RESULT_NOT_ATTEMPTED, result);
            EXPECT_EQ(3, retries);
        },
        [](const mpss_interaction_context_t *target, void *data) {
            auto &callback = *static_cast<CallbackState *>(data);
            callback.check(target);
            ++callback.observed->touches;
        },
        [](const mpss_interaction_context_t *target, bool success, void *data) {
            auto &callback = *static_cast<CallbackState *>(data);
            callback.check(target);
            ++callback.observed->completions;
            EXPECT_FALSE(success);
        },
        &state);

    // The adapter must copy the views into null-terminated C strings without exposing their suffixes.
    const auto handler = mpss::GetInteractionHandler();
    const mpss::InteractionContext target{
        std::string_view{"yubikey-tail"}.substr(0, 7), std::string_view{"35489220-tail"}.substr(0, 8),
        std::string_view{"my-key-tail"}.substr(0, 6), std::string_view{"reader-tail"}.substr(0, 6)};
    const std::optional<mpss::SecureString> pin = handler->request_pin(
        {.operation = "sign", .last_status = mpss::PinStatus::first_attempt, .retries_remaining = 3, .target = target});
    ASSERT_TRUE(pin.has_value());
    EXPECT_STREQ("unused-test-pin", pin->c_str());

    handler->notify_pin_result(target, mpss::PinResult::not_attempted, 3);
    handler->notify_touch_needed(target);
    handler->notify_touch_complete(target, false);

    EXPECT_EQ(1, observations.requests);
    EXPECT_EQ(1, observations.results);
    EXPECT_EQ(1, observations.touches);
    EXPECT_EQ(1, observations.completions);

    mpss_set_interaction_handler(nullptr, nullptr, nullptr, nullptr, nullptr);
    const auto empty = mpss::GetInteractionHandler();
    EXPECT_FALSE(empty->request_pin({.operation = "sign",
                                     .last_status = mpss::PinStatus::first_attempt,
                                     .retries_remaining = -1,
                                     .target = target}));
    EXPECT_NO_THROW(empty->notify_pin_result(target, mpss::PinResult::not_attempted, -1));
    EXPECT_NO_THROW(empty->notify_touch_needed(target));
    EXPECT_NO_THROW(empty->notify_touch_complete(target, false));
}

TEST(InteractionContextTest, CppNotificationsReceiveTarget)
{
    const auto previous = mpss::GetInteractionHandler();
    SCOPE_GUARD(mpss::GetOrSetInteractionHandler(previous));

    int results = 0;
    class TargetHandler : public mpss::InteractionHandler
    {
      public:
        explicit TargetHandler(int &calls) : calls_{calls}
        {
        }

        std::optional<mpss::SecureString> request_pin(const mpss::PinRequestContext &) override
        {
            return std::nullopt;
        }

        void notify_pin_result(const mpss::InteractionContext &target, mpss::PinResult, int) override
        {
            EXPECT_EQ("35489220", target.device_id);
            ++calls_;
        }

        void notify_touch_needed(const mpss::InteractionContext &target) override
        {
            EXPECT_EQ("reader", target.reader_name);
            ++calls_;
        }

        void notify_touch_complete(const mpss::InteractionContext &target, bool) override
        {
            EXPECT_EQ("my-key", target.key_name);
            ++calls_;
        }

      private:
        int &calls_;
    };

    mpss::GetOrSetInteractionHandler(std::make_shared<TargetHandler>(results));
    const auto handler = mpss::GetInteractionHandler();
    const mpss::InteractionContext target{"yubikey", "35489220", "my-key", "reader"};

    handler->notify_pin_result(target, mpss::PinResult::not_attempted, -1);
    handler->notify_touch_needed(target);
    handler->notify_touch_complete(target, false);
    EXPECT_EQ(3, results);
}
#endif

TEST(CApiErrorContract, AvailabilityQueriesHonorTheContract)
{
    // Prime the availability cache for every algorithm, so that the queries below take the
    // early-return path, where nothing else would incidentally overwrite a stale error.
    const char **available = mpss_get_available_algorithms();
    ASSERT_NE(nullptr, available);

    // A query that cannot be answered reports why. Each starts from a clean slate, so only the call
    // under test can account for the error.
    mpss_clear_error();
    EXPECT_FALSE(mpss_is_algorithm_available(nullptr));
    EXPECT_TRUE(mpss_has_error());

    mpss_clear_error();
    EXPECT_FALSE(mpss_is_algorithm_available("no_such_algorithm"));
    EXPECT_TRUE(mpss_has_error());

    mpss_clear_error();
    EXPECT_FALSE(mpss_is_algorithm_available_in_backend("no_such_algorithm", "os"));
    EXPECT_TRUE(mpss_has_error());

    mpss_clear_error();
    EXPECT_FALSE(mpss_is_algorithm_available_in_backend(nullptr, nullptr));
    EXPECT_TRUE(mpss_has_error());

    mpss_clear_error();
    EXPECT_FALSE(mpss_delete_key(nullptr));
    EXPECT_TRUE(mpss_has_error());

    mpss_clear_error();
    EXPECT_FALSE(mpss_delete_key_from_backend(test_key_name("no_such_key").c_str(), nullptr));
    EXPECT_TRUE(mpss_has_error());

    // Answering the question is the success, whichever way the answer goes, so a stale error does
    // not survive an availability query.
    if (nullptr != available[0])
    {
        EXPECT_FALSE(mpss_delete_key(""));
        ASSERT_TRUE(mpss_has_error());
        EXPECT_TRUE(mpss_is_algorithm_available(available[0]));
        EXPECT_FALSE(mpss_has_error());
    }

    EXPECT_FALSE(mpss_delete_key(""));
    ASSERT_TRUE(mpss_has_error());
    (void)mpss_get_available_algorithms();
    EXPECT_FALSE(mpss_has_error());

    // Discovery accessors leave the last error alone.
    (void)mpss_get_available_backends();
    (void)mpss_get_default_backend_name();
    EXPECT_FALSE(mpss_has_error());

    EXPECT_FALSE(mpss_delete_key(""));
    ASSERT_TRUE(mpss_has_error());
    (void)mpss_get_available_backends();
    (void)mpss_get_default_backend_name();
    EXPECT_TRUE(mpss_has_error());

    mpss_clear_error();
}

TEST_F(MPSSDigest, SHA256)
{
    std::random_device rd;
    for (int i = 0; i < 50; i++)
    {
        const std::size_t size = rd() % (1024 * 1024);
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd] { return static_cast<char>(rd() % 256); });
        TestDigest("SHA256", EVP_sha256, input_data);
    }
}

TEST_F(MPSSDigest, SHA384)
{
    std::random_device rd;
    for (int i = 0; i < 50; i++)
    {
        const std::size_t size = rd() % (1024 * 1024);
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd] { return static_cast<char>(rd() % 256); });
        TestDigest("SHA384", EVP_sha384, input_data);
    }
}

TEST_F(MPSSDigest, SHA512)
{
    std::random_device rd;
    for (int i = 0; i < 50; i++)
    {
        const std::size_t size = rd() % (1024 * 1024);
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd] { return static_cast<char>(rd() % 256); });
        TestDigest("SHA512", EVP_sha512, input_data);
    }
}

TEST_F(MPSSDigest, OneShotDigest)
{
    int no_cache = 0;
    const auto unquery_operation = [provider = mpss_prov](const OSSL_ALGORITHM *algorithms) {
        OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_DIGEST, algorithms);
    };
    const std::unique_ptr<const OSSL_ALGORITHM, decltype(unquery_operation)> digest_algorithms{
        OSSL_PROVIDER_query_operation(mpss_prov, OSSL_OP_DIGEST, &no_cache), unquery_operation};
    ASSERT_NE(nullptr, digest_algorithms);

    const OSSL_ALGORITHM *sha256_algorithm = nullptr;
    for (const OSSL_ALGORITHM *algorithm = digest_algorithms.get(); nullptr != algorithm->algorithm_names; ++algorithm)
    {
        if (has_algorithm_name(algorithm->algorithm_names, "SHA256"))
        {
            sha256_algorithm = algorithm;
            break;
        }
    }
    ASSERT_NE(nullptr, sha256_algorithm);

    OSSL_FUNC_digest_digest_fn *one_shot_digest = nullptr;
    for (const OSSL_DISPATCH *function = sha256_algorithm->implementation; 0 != function->function_id; ++function)
    {
        if (OSSL_FUNC_DIGEST_DIGEST == function->function_id)
        {
            one_shot_digest = OSSL_FUNC_digest_digest(function);
            break;
        }
    }
    ASSERT_NE(nullptr, one_shot_digest);

    void *provider_ctx = OSSL_PROVIDER_get0_provider_ctx(mpss_prov);
    ASSERT_NE(nullptr, provider_ctx);

    // Known-answer test: SHA-256("abc").
    const std::string_view abc = "abc";
    const unsigned char sha256_abc[] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

    std::random_device rd;
    for (int i = 0; i < 100; i++)
    {
        unsigned char mpss_digest[EVP_MAX_MD_SIZE];
        std::size_t mpss_digest_len = 0;
        ASSERT_EQ(1, one_shot_digest(provider_ctx, reinterpret_cast<const unsigned char *>(abc.data()), abc.size(),
                                     mpss_digest, &mpss_digest_len, sizeof(mpss_digest)));
        ASSERT_EQ(sizeof(sha256_abc), mpss_digest_len);
        ASSERT_TRUE(std::equal(mpss_digest, mpss_digest + mpss_digest_len, sha256_abc)); // NOLINT(modernize-use-ranges)

        // Compare the one-shot against the default provider on random input.
        const std::size_t size = rd() % 4096;
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd] { return static_cast<char>(rd() % 256); });

        ASSERT_EQ(1, one_shot_digest(provider_ctx, reinterpret_cast<const unsigned char *>(input_data.data()),
                                     input_data.size(), mpss_digest, &mpss_digest_len, sizeof(mpss_digest)));

        unsigned char default_digest[EVP_MAX_MD_SIZE];
        std::size_t default_digest_len = 0;
        ASSERT_EQ(1, EVP_Q_digest(mpss_libctx, "SHA256", "provider=default", input_data.data(), input_data.size(),
                                  default_digest, &default_digest_len));
        ASSERT_EQ(mpss_digest_len, default_digest_len);
        ASSERT_TRUE(
            std::equal(mpss_digest, mpss_digest + mpss_digest_len, default_digest)); // NOLINT(modernize-use-ranges)
    }
}

TEST(MPSS_OpenSSL, GetKeyDescriptors)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name_str = test_key_name("test_key_params");
    const char *key_name = key_name_str.c_str();
    const bool _ = mpss_delete_key(key_name);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),

        // There is a lot of flexibility in the algorithm name we pass here. For example,
        // this works just fine.
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa with p256 and sha256"), 0),
        OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);

    // Query gettable parameters
    OSSL_PARAM get_params[4];
    int is_hw = -1;
    int tier = -1;
    char storage_desc[256] = {0};
    get_params[0] = OSSL_PARAM_construct_int("is_hardware_backed", &is_hw);
    get_params[1] = OSSL_PARAM_construct_utf8_string("storage_description", storage_desc, sizeof(storage_desc));
    get_params[2] = OSSL_PARAM_construct_int("storage_tier", &tier);
    get_params[3] = OSSL_PARAM_END;

    ASSERT_EQ(1, EVP_PKEY_get_params(pkey, get_params));
    // is_hardware_backed should be 0 or 1
    ASSERT_TRUE(0 == is_hw || 1 == is_hw);
    // storage_description should not be empty
    ASSERT_GT(strlen(storage_desc), 0);

    // The tier is one this build names, and the other two parameters are what it reports: a
    // provider that answered them from anywhere else could disagree with the key it holds.
    ASSERT_GE(tier, MPSS_STORAGE_TIER_UNKNOWN);
    ASSERT_LT(tier, static_cast<int>(mpss::StorageTier::count));
    const mpss::StorageTierInfo tier_info = mpss::get_storage_tier_info(static_cast<mpss::StorageTier>(tier));
    EXPECT_EQ(tier, static_cast<int>(tier_info.tier));
    EXPECT_EQ(is_hw, tier_info.is_hardware_backed ? 1 : 0);
    EXPECT_EQ(std::string(storage_desc), std::string(tier_info.description));

    EVP_PKEY_free(pkey);
    ASSERT_EQ(1, mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, GenSetParamsRejectsNullString)
{
    // A keygen string param whose data pointer is NULL must be rejected cleanly:
    // OSSL_PARAM_get_utf8_string_ptr reports success with a nullptr value for such a param. No key is
    // generated here (set_params runs before generate), so this is backend-independent (never skipped).
    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));

    // data pointer NULL, type OSSL_PARAM_UTF8_STRING -> get_utf8_string_ptr yields (1, nullptr).
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("mpss_key_name", nullptr, 0), OSSL_PARAM_END};
    ASSERT_EQ(0, EVP_PKEY_CTX_set_params(ctx, params));

    EVP_PKEY_CTX_free(ctx);
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, GenerateRequiresAlgorithm)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    SCOPE_GUARD(OSSL_LIB_CTX_free(mpss_libctx));
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);
    SCOPE_GUARD(OSSL_PROVIDER_unload(mpss_prov));

    std::string key_name_str = test_key_name("test_key_requires_algorithm");
    char *key_name = key_name_str.data();
    const bool _ = mpss_delete_key(key_name);
    SCOPE_GUARD(mpss_delete_key(key_name));

    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        SCOPE_GUARD(EVP_PKEY_CTX_free(ctx));
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));

        char algorithm[] = "ecdsa_secp256r1_sha256";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_key_name", key_name, 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", algorithm, 0),
            OSSL_PARAM_END,
        };
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));

        EVP_PKEY *pkey = nullptr;
        SCOPE_GUARD(EVP_PKEY_free(pkey));
        ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
        ASSERT_NE(nullptr, pkey);
    }

    const auto expect_generate_rejected = [mpss_libctx](const OSSL_PARAM *params) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        SCOPE_GUARD(EVP_PKEY_CTX_free(ctx));
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));

        EVP_PKEY *pkey = nullptr;
        SCOPE_GUARD(EVP_PKEY_free(pkey));
        EXPECT_EQ(0, EVP_PKEY_generate(ctx, &pkey));
        EXPECT_EQ(nullptr, pkey);
    };

    OSSL_PARAM missing_algorithm[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", key_name, 0),
        OSSL_PARAM_END,
    };
    expect_generate_rejected(missing_algorithm);

    char empty_algorithm[] = "";
    OSSL_PARAM empty_algorithm_params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", key_name, 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", empty_algorithm, 0),
        OSSL_PARAM_END,
    };
    expect_generate_rejected(empty_algorithm_params);
}

TEST(MPSS_OpenSSL, DefaultBackendReturned)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name_str = test_key_name("test_key_default_backend");
    const char *key_name = key_name_str.c_str();
    const bool _ = mpss_delete_key(key_name);

    const char *default_backend = mpss_get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(strlen(default_backend), 0);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    // Create a key without specifying mpss_backend.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);

    // Query mpss_backend - should return the default backend even though we didn't set it.
    char backend_buf[256] = {0};
    OSSL_PARAM get_params[] = {OSSL_PARAM_construct_utf8_string("mpss_backend", backend_buf, sizeof(backend_buf)),
                               OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_get_params(pkey, get_params));
    ASSERT_STREQ(default_backend, backend_buf);

    EVP_PKEY_free(pkey);
    ASSERT_EQ(1, mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, ExplicitBackend)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name_str = test_key_name("test_key_explicit_backend");
    const char *key_name = key_name_str.c_str();
    const bool _ = mpss_delete_key(key_name);

    const char *default_backend = mpss_get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(strlen(default_backend), 0);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    // Create a key with an explicit backend.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(default_backend), 0), OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);

    // Query the backend via gettable params.
    char backend_buf[256] = {0};
    OSSL_PARAM get_params[] = {OSSL_PARAM_construct_utf8_string("mpss_backend", backend_buf, sizeof(backend_buf)),
                               OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_get_params(pkey, get_params));
    ASSERT_STREQ(default_backend, backend_buf);

    EVP_PKEY_free(pkey);
    ASSERT_EQ(1, mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, DeleteKeyFromBackend)
{
    const char **backends = mpss_get_available_backends();
    ASSERT_NE(nullptr, backends);
    if (nullptr == backends[0])
    {
        GTEST_SKIP() << "No backends available.";
    }

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    int backends_tested = 0;
    for (const char **b = backends; nullptr != *b; ++b)
    {
        const char *backend = *b;

        if (!mpss_is_algorithm_available_in_backend("ecdsa_secp256r1_sha256", backend))
        {
            continue;
        }

        const std::string key_name = test_key_name(std::string("test_delete_from_backend_") + backend);

        // Clean up a possible leftover from a previous run.
        mpss_delete_key_from_backend(key_name.c_str(), backend);

        // Create a key in this specific backend. The backend may be registered
        // without an underlying device being currently available (e.g., no
        // YubiKey plugged in), so treat key generation failure as "backend not
        // currently usable" and continue to the next one.
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
            OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(backend), 0), OSSL_PARAM_END};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
        EVP_PKEY *pkey = nullptr;
        if (1 != EVP_PKEY_generate(ctx, &pkey))
        {
            EVP_PKEY_CTX_free(ctx);
            continue;
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        // Delete the key from this specific backend.
        ASSERT_TRUE(mpss_delete_key_from_backend(key_name.c_str(), backend));

        // Deleting again succeeds: the request is that the name hold no key, and it already does.
        ASSERT_TRUE(mpss_delete_key_from_backend(key_name.c_str(), backend));

        ++backends_tested;
    }

    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);

    if (0 == backends_tested)
    {
        GTEST_SKIP() << "No backends support ecdsa_secp256r1_sha256.";
    }
}

// --- KeyPolicy C define / C++ enum agreement tests ---

TEST(KeyPolicyDefines, NoneMatchesCppEnum)
{
    static_assert(MPSS_KEY_POLICY_NONE == static_cast<std::uint64_t>(mpss::KeyPolicy::none));
}

TEST(KeyPolicyDefines, AppleSecureEnclaveUserPresenceMatchesCppEnum)
{
    static_assert(MPSS_KEY_POLICY_APPLE_SECURE_ENCLAVE_USER_PRESENCE ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::apple_secure_enclave_user_presence));
}

TEST(KeyPolicyDefines, YubikeyPinDefinesMatchCppEnum)
{
    static_assert(MPSS_KEY_POLICY_YUBIKEY_PIN_NEVER == static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_never));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE == static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_once));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_PIN_ALWAYS ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_always));
}

TEST(KeyPolicyDefines, YubikeyTouchDefinesMatchCppEnum)
{
    static_assert(MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_never));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_TOUCH_ALWAYS ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_always));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_TOUCH_CACHED ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_cached));
}

// --- KeyPolicy provider parameter pass-through test ---

TEST(MPSS_OpenSSL, CreateKeyWithPolicyParam)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name_str = test_key_name("test_key_policy_provider");
    const char *key_name = key_name_str.c_str();
    const bool _ = mpss_delete_key(key_name);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));

    // Pass mpss_key_policy = MPSS_KEY_POLICY_NONE through the provider parameter.
    std::uint64_t policy = MPSS_KEY_POLICY_NONE;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_construct_uint64("mpss_key_policy", &policy), OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    ASSERT_NE(nullptr, pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    ASSERT_TRUE(mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

// Fixture for the OSSL_STORE "open existing key by name" flow. Loads the mpss provider (key
// management / signing) and the default provider (to verify signatures against an extracted public
// key) into a private library context.
class MPSSStore : public ::testing::Test
{
  protected:
    OSSL_LIB_CTX *libctx = nullptr;
    OSSL_PROVIDER *mpss_prov = nullptr;
    OSSL_PROVIDER *default_prov = nullptr;

    void SetUp() override
    {
        libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, libctx);
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(libctx, "mpss", OSSL_provider_init));
        mpss_prov = OSSL_PROVIDER_load(libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);
        default_prov = OSSL_PROVIDER_load(libctx, "default");
        ASSERT_NE(nullptr, default_prov);
    }

    void TearDown() override
    {
        if (nullptr != default_prov)
        {
            OSSL_PROVIDER_unload(default_prov);
        }
        if (nullptr != mpss_prov)
        {
            OSSL_PROVIDER_unload(mpss_prov);
        }
        if (nullptr != libctx)
        {
            OSSL_LIB_CTX_free(libctx);
        }
    }

    // Open "mpss:<key_name>" through OSSL_STORE, optionally selecting a backend via the mpss_backend
    // ctx parameter, and return the reopened key (or nullptr if none was produced).
    EVP_PKEY *store_open_key(const std::string &key_name, const char *backend, const char *device_id = nullptr)
    {
        const std::string uri = "mpss:" + key_name;
        OSSL_PARAM backend_params[3]{};
        int count = 0;
        if (nullptr != backend)
        {
            backend_params[count++] = OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(backend), 0);
        }
        if (nullptr != device_id)
        {
            backend_params[count++] =
                OSSL_PARAM_construct_utf8_string("mpss_device_id", const_cast<char *>(device_id), 0);
        }
        backend_params[count] = OSSL_PARAM_END;
        OSSL_STORE_CTX *store = OSSL_STORE_open_ex(uri.c_str(), libctx, "provider=mpss", nullptr, nullptr,
                                                   backend_params, nullptr, nullptr);
        if (nullptr == store)
        {
            return nullptr;
        }
        EVP_PKEY *pkey = nullptr;
        while (0 == OSSL_STORE_eof(store))
        {
            OSSL_STORE_INFO *info = OSSL_STORE_load(store);
            if (nullptr == info)
            {
                continue;
            }
            if (OSSL_STORE_INFO_PKEY == OSSL_STORE_INFO_get_type(info))
            {
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
            }
            OSSL_STORE_INFO_free(info);
        }
        OSSL_STORE_close(store);
        return pkey;
    }

    // Delete "mpss:<key_name>" through OSSL_STORE_delete, optionally selecting a backend via the
    // mpss_backend parameter. Returns the OSSL_STORE_delete result (1 on success, 0 otherwise).
    int store_delete_key(const std::string &key_name, const char *backend, const char *device_id = nullptr)
    {
        const std::string uri = "mpss:" + key_name;
        OSSL_PARAM backend_params[3]{};
        int count = 0;
        if (nullptr != backend)
        {
            backend_params[count++] = OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(backend), 0);
        }
        if (nullptr != device_id)
        {
            backend_params[count++] =
                OSSL_PARAM_construct_utf8_string("mpss_device_id", const_cast<char *>(device_id), 0);
        }
        backend_params[count] = OSSL_PARAM_END;
        return OSSL_STORE_delete(uri.c_str(), libctx, "provider=mpss", nullptr, nullptr, backend_params);
    }

    // Create a key (optionally on an explicit backend / with a key policy), close it, reopen it by
    // name through OSSL_STORE, and prove the reopened handle is the same key (identical SPKI) and
    // usable (its signature verifies under the default provider against the created key's public key).
    //
    // creation_may_be_unavailable marks a backend that can be present and reachable yet unable to
    // create, one whose credentials are not configured for instance. That is a state the run was
    // never set up for rather than a defect, so it skips.
    void reopen_roundtrip(const char *key_name, const char *backend, std::uint64_t key_policy,
                          bool creation_may_be_unavailable = false)
    {
        const bool from_backend = (nullptr != backend);
        if (from_backend)
        {
            mpss_delete_key_from_backend(key_name, backend);
        }
        else
        {
            mpss_delete_key(key_name);
        }

        // Create and capture the public key (SubjectPublicKeyInfo DER).
        evp_pkey_ptr pkey = GenerateKey(libctx, key_name, backend, key_policy);
        if (nullptr == pkey && creation_may_be_unavailable)
        {
            GTEST_SKIP() << "Backend cannot create keys in its current state: " << mpss_get_error();
        }
        ASSERT_NE(nullptr, pkey);

        unsigned char *spki_created = nullptr;
        const int spki_created_len = i2d_PUBKEY(pkey.get(), &spki_created);
        ASSERT_GT(spki_created_len, 0);
        pkey.reset(); // close

        // Reopen by name (selecting the backend when one was given).
        EVP_PKEY *reopened = store_open_key(key_name, backend);
        ASSERT_NE(nullptr, reopened);

        // Identity: the reopened key exposes the same public key as the created one.
        unsigned char *spki_reopened = nullptr;
        const int spki_reopened_len = i2d_PUBKEY(reopened, &spki_reopened);
        ASSERT_GT(spki_reopened_len, 0);
        ASSERT_EQ(spki_created_len, spki_reopened_len);
        ASSERT_EQ(0, memcmp(spki_created, spki_reopened, static_cast<std::size_t>(spki_created_len)));

        // Usability: sign with the reopened key, verify under the default provider against the
        // captured public key.
        const std::string_view message = "reopened key signing test";
        const auto *msg = reinterpret_cast<const unsigned char *>(message.data());
        EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, sign_ctx);
        ASSERT_EQ(1, EVP_DigestSignInit_ex(sign_ctx, nullptr, "SHA256", libctx, "provider=mpss", reopened, nullptr));
        std::size_t sig_len = 0;
        ASSERT_EQ(1, EVP_DigestSign(sign_ctx, nullptr, &sig_len, msg, message.size()));
        std::vector<unsigned char> sig(sig_len);
        ASSERT_EQ(1, EVP_DigestSign(sign_ctx, sig.data(), &sig_len, msg, message.size()));
        sig.resize(sig_len);
        EVP_MD_CTX_free(sign_ctx);

        const unsigned char *spki_ptr = spki_created;
        EVP_PKEY *verify_key = d2i_PUBKEY_ex(nullptr, &spki_ptr, spki_created_len, libctx, "provider=default");
        ASSERT_NE(nullptr, verify_key);
        EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, verify_ctx);
        ASSERT_EQ(
            1, EVP_DigestVerifyInit_ex(verify_ctx, nullptr, "SHA256", libctx, "provider=default", verify_key, nullptr));
        ASSERT_EQ(1, EVP_DigestVerify(verify_ctx, sig.data(), sig.size(), msg, message.size()));
        EVP_MD_CTX_free(verify_ctx);

        EVP_PKEY_free(verify_key);
        EVP_PKEY_free(reopened);
        OPENSSL_free(spki_created);
        OPENSSL_free(spki_reopened);

        // The mpss_backend parameter must actually be consulted, not silently ignored: opening the
        // (still-present) key with a nonexistent backend must fail closed rather than fall back to
        // the default backend. This is what distinguishes routing from defaulting when the target
        // backend happens to be the default (e.g. "os" on macOS).
        if (from_backend)
        {
            ASSERT_EQ(nullptr, store_open_key(key_name, "nonexistent"));
        }

        // Delete through the OSSL-native path (OSSL_STORE_delete), selecting the backend when given.
        ASSERT_EQ(1, store_delete_key(key_name, backend));
    }
};

TEST_F(MPSSStore, ReopenByNameDefaultBackend)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string reopen_name = test_key_name("test_key_reopen_by_name");
    reopen_roundtrip(reopen_name.c_str(), nullptr, MPSS_KEY_POLICY_NONE);
    ASSERT_FALSE(HasFatalFailure());

    // A deleted / nonexistent name yields no key: the store delivers the reference object, but key
    // management load fails to open it, so nothing is produced.
    ASSERT_EQ(nullptr, store_open_key(reopen_name, nullptr));

    // A URI with an empty key name is rejected when the store is opened.
    ASSERT_EQ(nullptr,
              OSSL_STORE_open_ex("mpss:", libctx, "provider=mpss", nullptr, nullptr, nullptr, nullptr, nullptr));
}

TEST_F(MPSSStore, ReopenByNameExplicitBackendOS)
{
    if (!mpss_is_algorithm_available_in_backend("ecdsa_secp256r1_sha256", "os"))
    {
        GTEST_SKIP() << "os backend not available";
    }

    // Selecting the backend explicitly through the mpss_backend store parameter must reopen the same
    // key that key generation created on that backend.
    const std::string reopen_os_name = test_key_name("test_key_reopen_os");
    reopen_roundtrip(reopen_os_name.c_str(), "os", MPSS_KEY_POLICY_NONE);
}

TEST_F(MPSSStore, DeleteByName)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name_str = test_key_name("test_key_delete_by_name");
    const char *key_name = key_name_str.c_str();
    mpss_delete_key(key_name);

    // Create a key on the default backend.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM gen_params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_construct_end()};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, gen_params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Delete it through OSSL_STORE_delete, then confirm it is gone. A second delete also succeeds:
    // the name already holds nothing, which is what the call asks for.
    ASSERT_EQ(1, store_delete_key(key_name, nullptr));
    ASSERT_EQ(nullptr, store_open_key(key_name, nullptr));
    ASSERT_EQ(1, store_delete_key(key_name, nullptr));
}

TEST_F(MPSSStore, ExportTypesMatchSupportedSelections)
{
    int no_cache = 0;
    const auto unquery_operation = [provider = mpss_prov](const OSSL_ALGORITHM *algorithms) {
        OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_KEYMGMT, algorithms);
    };
    const std::unique_ptr<const OSSL_ALGORITHM, decltype(unquery_operation)> keymgmt_algorithms{
        OSSL_PROVIDER_query_operation(mpss_prov, OSSL_OP_KEYMGMT, &no_cache), unquery_operation};
    ASSERT_NE(nullptr, keymgmt_algorithms);

    const OSSL_ALGORITHM *ec_algorithm = nullptr;
    for (const OSSL_ALGORITHM *algorithm = keymgmt_algorithms.get(); nullptr != algorithm->algorithm_names; ++algorithm)
    {
        if (has_algorithm_name(algorithm->algorithm_names, "EC"))
        {
            ec_algorithm = algorithm;
            break;
        }
    }
    ASSERT_NE(nullptr, ec_algorithm);

    OSSL_FUNC_keymgmt_export_types_fn *export_types = nullptr;
    for (const OSSL_DISPATCH *function = ec_algorithm->implementation; 0 != function->function_id; ++function)
    {
        if (OSSL_FUNC_KEYMGMT_EXPORT_TYPES == function->function_id)
        {
            export_types = OSSL_FUNC_keymgmt_export_types(function);
            break;
        }
    }
    ASSERT_NE(nullptr, export_types);

    const auto expect_types = [export_types](int selection, bool has_group, bool has_public_key) {
        SCOPED_TRACE(selection);
        const OSSL_PARAM *types = export_types(selection);
        ASSERT_NE(nullptr, types);
        EXPECT_EQ(has_group, nullptr != OSSL_PARAM_locate_const(types, OSSL_PKEY_PARAM_GROUP_NAME));
        EXPECT_EQ(has_public_key, nullptr != OSSL_PARAM_locate_const(types, OSSL_PKEY_PARAM_PUB_KEY));
    };

    expect_types(OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, true, false);
    expect_types(OSSL_KEYMGMT_SELECT_PUBLIC_KEY, false, true);
    expect_types(OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY, true, true);
    expect_types(OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, false, false);
    expect_types(OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, true, false);
    expect_types(OSSL_KEYMGMT_SELECT_PRIVATE_KEY, false, false);
    expect_types(OSSL_KEYMGMT_SELECT_KEYPAIR, false, false);
    expect_types(OSSL_KEYMGMT_SELECT_ALL, false, false);
}

TEST_F(MPSSStore, ExportRefusesPrivateKeySelection)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name_str = test_key_name("test_key_export_refuses_private");
    const char *key_name = key_name_str.c_str();
    mpss_delete_key(key_name);
    // The key is persisted in the backend, so remove it even if an assertion below returns early.
    SCOPE_GUARD(mpss_delete_key(key_name));

    EVP_PKEY *pkey = nullptr;
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        SCOPE_GUARD(EVP_PKEY_CTX_free(ctx));

        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        OSSL_PARAM gen_params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
            OSSL_PARAM_construct_end()};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, gen_params));
        ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    }
    SCOPE_GUARD(EVP_PKEY_free(pkey));

    OSSL_PARAM *public_params = nullptr;
    EXPECT_EQ(1, EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &public_params));
    EXPECT_NE(nullptr, OSSL_PARAM_locate_const(public_params, OSSL_PKEY_PARAM_PUB_KEY));
    OSSL_PARAM_free(public_params);

    OSSL_PARAM *domain_params = nullptr;
    ASSERT_EQ(1, EVP_PKEY_todata(pkey, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, &domain_params));
    EXPECT_NE(nullptr, OSSL_PARAM_locate_const(domain_params, OSSL_PKEY_PARAM_GROUP_NAME));
    OSSL_PARAM_free(domain_params);

    OSSL_PARAM *other_params = nullptr;
    ASSERT_EQ(1, EVP_PKEY_todata(pkey, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, &other_params));
    EXPECT_EQ(nullptr, OSSL_PARAM_locate_const(other_params, OSSL_PKEY_PARAM_GROUP_NAME));
    OSSL_PARAM_free(other_params);

    for (const int selection : {EVP_PKEY_KEYPAIR, EVP_PKEY_PRIVATE_KEY})
    {
        OSSL_PARAM *params = nullptr;
        EXPECT_EQ(0, EVP_PKEY_todata(pkey, selection, &params)) << "selection " << selection << " was exported";
        OSSL_PARAM_free(params);
    }
}

TEST_F(MPSSStore, AdvertisesGroupNameParam)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name_str = test_key_name("test_key_group_name_param");
    const char *key_name = key_name_str.c_str();
    mpss_delete_key(key_name);
    // The key is persisted in the backend, so remove it even if an assertion below returns early.
    SCOPE_GUARD(mpss_delete_key(key_name));

    EVP_PKEY *pkey = nullptr;
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        SCOPE_GUARD(EVP_PKEY_CTX_free(ctx));

        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        OSSL_PARAM gen_params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
            OSSL_PARAM_construct_end()};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, gen_params));
        ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    }
    SCOPE_GUARD(EVP_PKEY_free(pkey));

    EXPECT_NE(nullptr, OSSL_PARAM_locate_const(EVP_PKEY_gettable_params(pkey), OSSL_PKEY_PARAM_GROUP_NAME));

    char group_name[80] = {};
    std::size_t group_name_len = 0;
    ASSERT_EQ(1, EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name, sizeof(group_name),
                                                &group_name_len));
    EXPECT_STREQ(SN_X9_62_prime256v1, group_name);
}

#ifdef MPSS_BACKEND_YUBIKEY
TEST_F(MPSSStore, HostVerificationDoesNotSelectTheMpssProvider)
{
    const evp_pkey_ptr key(EVP_PKEY_Q_keygen(libctx, "provider=default", "EC", SN_X9_62_prime256v1));
    ASSERT_NE(nullptr, key);
    const evp_pkey_ctx_ptr signing(EVP_PKEY_CTX_new_from_pkey(libctx, key.get(), "provider=default"));
    ASSERT_NE(nullptr, signing);
    ASSERT_EQ(1, EVP_PKEY_sign_init(signing.get()));
    ASSERT_EQ(1, EVP_PKEY_CTX_set_signature_md(signing.get(), EVP_sha256()));
    const std::array<unsigned char, 32> hash{};
    std::size_t written = 0;
    ASSERT_EQ(1, EVP_PKEY_sign(signing.get(), nullptr, &written, hash.data(), hash.size()));
    std::vector<unsigned char> signature(written);
    ASSERT_EQ(1, EVP_PKEY_sign(signing.get(), signature.data(), &written, hash.data(), hash.size()));
    signature.resize(written);
    std::array<unsigned char, 65> public_key{};
    ASSERT_EQ(1, EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY, public_key.data(),
                                                 public_key.size(), &written));
    ASSERT_EQ(public_key.size(), written);

    OSSL_LIB_CTX *verification_context = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, verification_context);
    SCOPE_GUARD(OSSL_LIB_CTX_free(verification_context));
    OSSL_PROVIDER *null_provider = OSSL_PROVIDER_load(verification_context, "null");
    ASSERT_NE(nullptr, null_provider);
    SCOPE_GUARD(OSSL_PROVIDER_unload(null_provider));
    ASSERT_EQ(1, EVP_set_default_properties(verification_context, "provider=unavailable"));
    OSSL_LIB_CTX *previous_context = OSSL_LIB_CTX_set0_default(verification_context);
    SCOPE_GUARD(OSSL_LIB_CTX_set0_default(previous_context));

    EXPECT_TRUE(mpss::verify(std::as_bytes(std::span{hash}), std::as_bytes(std::span{public_key}),
                             mpss::Algorithm::ecdsa_secp256r1_sha256, std::as_bytes(std::span{signature}), "yubikey"));
    signature.back() ^= 1;
    EXPECT_FALSE(mpss::verify(std::as_bytes(std::span{hash}), std::as_bytes(std::span{public_key}),
                              mpss::Algorithm::ecdsa_secp256r1_sha256, std::as_bytes(std::span{signature}), "yubikey"));
}

TEST_F(MPSSStore, ReopenByNameYubiKey)
{
    const auto devices = mpss::get_available_devices("yubikey");
    if (!devices || devices->empty())
    {
        GTEST_SKIP() << "YubiKey device not available";
    }
    if (!mpss_is_algorithm_available_in_backend("ecdsa_secp256r1_sha256", "yubikey"))
    {
        GTEST_SKIP() << "YubiKey backend not available";
    }

    // touch=never so signing does not block on a physical touch during automated runs; pin=once uses
    // the configured PIN (MPSS_YUBIKEY_PIN) for the signing operation.
    const std::string reopen_yk_name = test_key_name("test_key_reopen_yk");
    reopen_roundtrip(reopen_yk_name.c_str(), "yubikey",
                     MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER | MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE,
                     /* creation_may_be_unavailable */ true);
}
#endif // MPSS_BACKEND_YUBIKEY

TEST_F(MPSSStore, ReferencePemDecoderRejectsLegacyFormatForExistingKey)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = reference_fixture_key_name();
    mpss_delete_key(key_name.c_str());
    SCOPE_GUARD(mpss_delete_key(key_name.c_str()));

    evp_pkey_ptr key = GenerateKey(libctx, key_name);
    if (nullptr == key)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }
    key.reset();

    for (const std::string_view backend : {std::string_view{}, std::string_view{mpss::get_default_backend_name()}})
    {
        SCOPED_TRACE(backend);
        const evp_pkey_ptr opened(store_open_key(key_name, backend.empty() ? nullptr : backend.data()));
        ASSERT_NE(nullptr, opened);
        ERR_clear_error();
        EXPECT_EQ(nullptr, DecodeReferencePem(libctx, LegacyReferencePemFor(backend, key_name)).get());
        bool bad_encoding = false;
        for (unsigned long error = ERR_get_error(); 0 != error; error = ERR_get_error())
        {
            bad_encoding |= ERR_LIB_PROV == ERR_GET_LIB(error) && PROV_R_BAD_ENCODING == ERR_GET_REASON(error);
        }
        EXPECT_TRUE(bad_encoding);
    }
}

struct MalformedLoadReference
{
    std::string_view scenario;
    std::string_view body;
};

class MPSSReferencePemRejects : public MPSSStore, public ::testing::WithParamInterface<MalformedLoadReference>
{
};

// Scenario: a PEM carrying our label holds a load reference the decoder cannot use.
// Expected behavior: it decodes to no key.
TEST_P(MPSSReferencePemRejects, MalformedLoadReferenceDecodesToNoKey)
{
    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, ReferencePem(Base64(GetParam().body))).get());
}

INSTANTIATE_TEST_SUITE_P(MalformedLoadReferences, MPSSReferencePemRejects,
                         ::testing::Values(MalformedLoadReference{"LegacyDefaultBackend", "\0mpss_absent_key"sv},
                                           MalformedLoadReference{"LegacyExplicitBackend", "os\0mpss_absent_key"sv},
                                           MalformedLoadReference{"NoSeparator", "ab"sv},
                                           MalformedLoadReference{"SecondSeparator", "os\0extra\0name"sv}),
                         [](const ::testing::TestParamInfo<MalformedLoadReference> &info) {
                             return std::string(info.param.scenario);
                         });

// Scenario: a PEM carrying our label holds a body that is not base64 at all.
// Expected behavior: it decodes to no key.
TEST_F(MPSSStore, ReferencePemDecoderRejectsNonBase64Body)
{
    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, ReferencePem("!!!not-base64!!!")).get());
}

// Scenario: a PEM carries our label but a body the decoder cannot use, which aborts the decoder
// chain rather than deferring to another decoder.
// Expected behavior: the reason reaches the OpenSSL error queue. OpenSSL reports a generic decode
// failure on its own, which does not distinguish a file that is not ours from one that is ours and
// malformed; the specific reason is what makes that diagnosable.
TEST_F(MPSSStore, ReferencePemDecoderReportsWhyItRejectedOurOwnLabel)
{
    ERR_clear_error();
    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, ReferencePem(Base64("no-separator"sv))).get());

    // The queue also carries OpenSSL's own decode errors, and their order is not ours to rely on,
    // so search it rather than inspecting only the last entry.
    bool found = false;
    for (unsigned long e = ERR_get_error(); 0 != e; e = ERR_get_error())
    {
        if (ERR_LIB_PROV == ERR_GET_LIB(e) && PROV_R_BAD_ENCODING == ERR_GET_REASON(e))
        {
            found = true;
        }
    }
    EXPECT_TRUE(found) << "the decoder aborted the chain without reporting why";
    ERR_clear_error();
}

// Scenario: a PEM that is not ours is offered to the decoder chain.
// Expected behavior: it decodes to no MPSS key.
TEST_F(MPSSStore, ReferencePemDecoderRejectsForeignPem)
{
    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, "-----BEGIN PRIVATE KEY-----\n"
                                                  "TUVTU0FHRQ==\n"
                                                  "-----END PRIVATE KEY-----\n")
                           .get());
}

TEST_F(MPSSStore, ReferencePemFramingPreservesFollowingRecords)
{
    const evp_pkey_ptr key = GenerateFramingKey(libctx);
    ASSERT_NE(nullptr, key);
    const std::string body = BoundReference("os", "framing-only", "", PublicKeyDer(key.get()));
    const std::string pem = ReferencePem(Base64(body));
    const std::string records = pem + pem;
    const bio_ptr input(BIO_new_mem_buf(records.data(), static_cast<int>(records.size())));
    ASSERT_NE(nullptr, input);

    std::string reference;
    ASSERT_EQ(1, DecodeReferenceObject(libctx, input.get(), reference));
    EXPECT_EQ(body, reference);
    EXPECT_EQ(pem.size(), BIO_ctrl_pending(input.get()));

    reference.clear();
    ASSERT_EQ(1, DecodeReferenceObject(libctx, input.get(), reference));
    EXPECT_EQ(body, reference);
    EXPECT_EQ(0U, BIO_ctrl_pending(input.get()));
}

TEST_F(MPSSStore, ReferencePemFramingRejectsMidLineDelimiters)
{
    const evp_pkey_ptr key = GenerateFramingKey(libctx);
    ASSERT_NE(nullptr, key);
    const std::string body = BoundReference("os", "framing-only", "", PublicKeyDer(key.get()));
    const std::string pem = ReferencePem(Base64(body));

    // A line-buffer boundary must not turn the middle of a physical line into a BEGIN line.
    for (const std::size_t prefix_size : {std::size_t{511}, std::size_t{1022}})
    {
        SCOPED_TRACE(prefix_size);
        const std::string input_text = std::string(prefix_size, 'x') + pem;
        const bio_ptr input(BIO_new_mem_buf(input_text.data(), static_cast<int>(input_text.size())));
        ASSERT_NE(nullptr, input);
        std::string reference;
        EXPECT_EQ(0, DecodeReferenceObject(libctx, input.get(), reference));
        EXPECT_TRUE(reference.empty());
        ERR_clear_error();
    }
}

TEST_F(MPSSStore, ReferencePemFramingLimitsConsumedInput)
{
    constexpr std::size_t input_limit = 8192;
    const std::string begin = "-----BEGIN MPSS KEY REFERENCE-----\n";
    const std::string input_text = begin + std::string(input_limit * 2, 'A');
    std::size_t consumed = 0;
    const bio_ptr input(BIO_new_mem_buf(input_text.data(), static_cast<int>(input_text.size())));
    ASSERT_NE(nullptr, input);

    // Count actual reads even if the decoder framework later restores the stream position.
    BIO_set_callback_arg(input.get(), reinterpret_cast<char *>(&consumed));
    BIO_set_callback_ex(
        input.get(),
        // NOLINTNEXTLINE(readability-non-const-parameter) - OpenSSL requires this callback signature.
        [](BIO *bio, int operation, const char *, std::size_t, int, long, int result, std::size_t *processed) -> long {
            if ((BIO_CB_READ | BIO_CB_RETURN) == operation && 0 < result && nullptr != processed)
            {
                *reinterpret_cast<std::size_t *>(BIO_get_callback_arg(bio)) += *processed;
            }
            return result;
        });

    std::string reference;
    EXPECT_EQ(0, DecodeReferenceObject(libctx, input.get(), reference));
    EXPECT_TRUE(reference.empty());
    EXPECT_EQ(input_limit, consumed);
    EXPECT_LE(input_text.size() - BIO_ctrl_pending(input.get()), input_limit);
    ERR_clear_error();
}

TEST_F(MPSSStore, ReferencePemFramingAcceptsCompleteRecordsWithinBudget)
{
    constexpr std::size_t input_limit = 8192;
    const evp_pkey_ptr key = GenerateFramingKey(libctx);
    ASSERT_NE(nullptr, key);
    const std::string body = BoundReference("os", "framing-only", "", PublicKeyDer(key.get()));
    const std::string pem = ReferencePem(Base64(body));
    ASSERT_LT(pem.size() + 1, input_limit);
    const std::string at_limit = std::string(input_limit - pem.size() - 1, 'x') + "\n" + pem;

    std::string crlf;
    for (const char c : pem)
    {
        if ('\n' == c)
        {
            crlf.push_back('\r');
        }
        crlf.push_back(c);
    }

    for (const auto &record : {pem, crlf, pem.substr(0, pem.size() - 1), at_limit})
    {
        const bio_ptr input(BIO_new_mem_buf(record.data(), static_cast<int>(record.size())));
        ASSERT_NE(nullptr, input);
        std::string reference;
        EXPECT_EQ(1, DecodeReferenceObject(libctx, input.get(), reference));
        EXPECT_EQ(body, reference);
        EXPECT_EQ(0U, BIO_ctrl_pending(input.get()));
    }

    const std::string over_limit = "x" + at_limit;
    const bio_ptr input(BIO_new_mem_buf(over_limit.data(), static_cast<int>(over_limit.size())));
    ASSERT_NE(nullptr, input);
    std::string reference;
    EXPECT_EQ(0, DecodeReferenceObject(libctx, input.get(), reference));
    EXPECT_TRUE(reference.empty());
    EXPECT_EQ(1U, BIO_ctrl_pending(input.get()));
    ERR_clear_error();

    // At the budget boundary, an END without LF cannot be distinguished from a truncated physical line.
    const std::string no_final_lf = "x" + at_limit.substr(0, at_limit.size() - 1);
    ASSERT_EQ(input_limit, no_final_lf.size());
    for (const auto &record : {no_final_lf, no_final_lf + "unread"})
    {
        const bio_ptr bounded(BIO_new_mem_buf(record.data(), static_cast<int>(record.size())));
        ASSERT_NE(nullptr, bounded);
        reference.clear();
        EXPECT_EQ(0, DecodeReferenceObject(libctx, bounded.get(), reference));
        EXPECT_TRUE(reference.empty());
        EXPECT_EQ(record.size() - input_limit, BIO_ctrl_pending(bounded.get()));
        ERR_clear_error();
    }
}

TEST_F(MPSSStore, ReferencePemFramingStopsAtMismatchedFooter)
{
    const evp_pkey_ptr key = GenerateFramingKey(libctx);
    ASSERT_NE(nullptr, key);
    const std::string body = BoundReference("os", "framing-only", "", PublicKeyDer(key.get()));
    const std::string pem = ReferencePem(Base64(body));
    const std::string malformed =
        "-----BEGIN MPSS KEY REFERENCE-----\n" + Base64(body) + "\n-----END DIFFERENT LABEL-----\n";
    const std::string input_text = malformed + pem;
    const bio_ptr input(BIO_new_mem_buf(input_text.data(), static_cast<int>(input_text.size())));
    ASSERT_NE(nullptr, input);

    ERR_clear_error();
    std::string reference;
    EXPECT_EQ(0, DecodeReferenceObject(libctx, input.get(), reference));
    EXPECT_TRUE(reference.empty());
    EXPECT_EQ(pem.size(), BIO_ctrl_pending(input.get()));
    bool bad_encoding = false;
    for (unsigned long error = ERR_get_error(); 0 != error; error = ERR_get_error())
    {
        bad_encoding |= ERR_LIB_PROV == ERR_GET_LIB(error) && PROV_R_BAD_ENCODING == ERR_GET_REASON(error);
    }
    EXPECT_TRUE(bad_encoding);
}

TEST_F(MPSSStore, ReferencePemForeignProbePreservesExistingErrors)
{
    const std::string input_text = "-----BEGIN FOREIGN OBJECT-----\nAAAA\n-----END FOREIGN OBJECT-----\n" +
                                   ReferencePem(Base64("not-a-reference"));
    const bio_ptr input(BIO_new_mem_buf(input_text.data(), static_cast<int>(input_text.size())));
    ASSERT_NE(nullptr, input);

    ERR_clear_error();
    ERR_raise(ERR_LIB_USER, 42);
    const unsigned long existing_error = ERR_peek_last_error();
    ASSERT_NE(0UL, existing_error);
    std::string reference;
    EXPECT_EQ(0, DecodeReferenceObject(libctx, input.get(), reference));
    EXPECT_TRUE(reference.empty());
    EXPECT_EQ(existing_error, ERR_get_error());
    for (unsigned long error = ERR_get_error(); 0 != error; error = ERR_get_error())
    {
        EXPECT_FALSE(ERR_LIB_PROV == ERR_GET_LIB(error) && PROV_R_BAD_ENCODING == ERR_GET_REASON(error));
    }
}

TEST_F(MPSSStore, ReferencePemFramingKeepsBufferedFragmentsOnTheSameLine)
{
    const evp_pkey_ptr key = GenerateFramingKey(libctx);
    ASSERT_NE(nullptr, key);
    const std::string body = BoundReference("os", "framing-only", "", PublicKeyDer(key.get()));
    const std::string pem = ReferencePem(Base64(body));

    BIO *reader_raw = nullptr;
    BIO *writer_raw = nullptr;
    ASSERT_EQ(1, BIO_new_bio_pair(&reader_raw, 0, &writer_raw, 0));
    bio_ptr reader(reader_raw);
    const bio_ptr writer(writer_raw);
    bio_ptr buffered(BIO_new(BIO_f_buffer()));
    ASSERT_NE(nullptr, buffered);
    ASSERT_NE(nullptr, BIO_push(buffered.get(), reader.get()));
    static_cast<void>(reader.release());
    ASSERT_EQ(6, BIO_write(writer.get(), "prefix", 6));

    struct Feed
    {
        BIO *writer = nullptr;
        const std::string *suffix = nullptr;
        bool sent = false;
    } feed{.writer = writer.get(), .suffix = &pem};
    BIO_set_callback_arg(buffered.get(), reinterpret_cast<char *>(&feed));
    BIO_set_callback_ex(
        buffered.get(),
        // NOLINTNEXTLINE(readability-non-const-parameter) - OpenSSL requires this callback signature.
        [](BIO *bio, int operation, const char *, std::size_t, int, long, int result, std::size_t *processed) -> long {
            if (((BIO_CB_GETS | BIO_CB_RETURN) == operation || (BIO_CB_READ | BIO_CB_RETURN) == operation) &&
                0 < result && nullptr != processed && 0 < *processed)
            {
                auto &state = *reinterpret_cast<Feed *>(BIO_get_callback_arg(bio));
                if (!state.sent)
                {
                    state.sent = true;
                    EXPECT_EQ(static_cast<int>(state.suffix->size()),
                              BIO_write(state.writer, state.suffix->data(), static_cast<int>(state.suffix->size())));
                    EXPECT_EQ(1, BIO_shutdown_wr(state.writer));
                }
            }
            return result;
        });
    SCOPE_GUARD(BIO_set_callback_ex(buffered.get(), nullptr));

    std::string reference;
    EXPECT_EQ(0, DecodeReferenceObject(libctx, buffered.get(), reference));
    EXPECT_TRUE(reference.empty());
    EXPECT_TRUE(feed.sent);
    ERR_clear_error();
}

TEST_F(MPSSStore, ReferencePemFramingCountsFileBytesContainingNul)
{
    constexpr std::size_t input_limit = 8192;
    const std::string input_text = std::string{"x\0", 2} + std::string(input_limit - 3, 'x') + "\n" +
                                   "-----BEGIN MPSS KEY REFERENCE-----\n" + std::string(1024, 'A');
    const auto path = std::filesystem::temp_directory_path() / (test_key_name("pem_framing") + ".pem");
    SCOPE_GUARD(std::filesystem::remove(path));
    {
        std::ofstream output(path, std::ios::binary);
        ASSERT_TRUE(output.is_open());
        output.write(input_text.data(), static_cast<std::streamsize>(input_text.size()));
        ASSERT_TRUE(output.good());
    }
    const bio_ptr input(BIO_new_file(path.string().c_str(), "rb"));
    ASSERT_NE(nullptr, input);

    std::string reference;
    EXPECT_EQ(0, DecodeReferenceObject(libctx, input.get(), reference));
    EXPECT_TRUE(reference.empty());
    const long position = BIO_tell(input.get());
    ASSERT_LE(0L, position);
    EXPECT_LE(position, static_cast<long>(input_limit));
    ERR_clear_error();
}

TEST_F(MPSSStore, ReferencePemFramingDoesNotTreatRetryAsEndOfLine)
{
    const evp_pkey_ptr key = GenerateFramingKey(libctx);
    ASSERT_NE(nullptr, key);
    const std::string body = BoundReference("os", "framing-only", "", PublicKeyDer(key.get()));
    std::string pending = ReferencePem(Base64(body));
    pending.pop_back();

    BIO *reader_raw = nullptr;
    BIO *writer_raw = nullptr;
    ASSERT_EQ(1, BIO_new_bio_pair(&reader_raw, 0, &writer_raw, 0));
    bio_ptr reader(reader_raw);
    const bio_ptr writer(writer_raw);
    bio_ptr buffered(BIO_new(BIO_f_buffer()));
    ASSERT_NE(nullptr, buffered);
    ASSERT_NE(nullptr, BIO_push(buffered.get(), reader.get()));
    static_cast<void>(reader.release());
    ASSERT_EQ(static_cast<int>(pending.size()),
              BIO_write(writer.get(), pending.data(), static_cast<int>(pending.size())));

    // The producer has not closed its side: further footer characters can still arrive.
    std::string reference;
    EXPECT_EQ(0, DecodeReferenceObject(libctx, buffered.get(), reference));
    EXPECT_TRUE(reference.empty());
    bool bad_encoding = false;
    for (unsigned long error = ERR_get_error(); 0 != error; error = ERR_get_error())
    {
        bad_encoding |= ERR_LIB_PROV == ERR_GET_LIB(error) && PROV_R_BAD_ENCODING == ERR_GET_REASON(error);
    }
    EXPECT_TRUE(bad_encoding);
}

TEST_F(MPSSStore, BoundReferenceRejectsMalformedDerBeforeOpening)
{
    const evp_pkey_ptr public_key(EVP_PKEY_Q_keygen(libctx, "provider=default", "EC", SN_X9_62_prime256v1));
    ASSERT_NE(nullptr, public_key);
    const std::string spki = PublicKeyDer(public_key.get());
    ASSERT_FALSE(spki.empty());
    const std::string valid = BoundReference("os", "mpss_bound_parse_only", "", spki);

    std::vector<std::string> malformed;
    std::vector<std::string> unsupported_bodies;

    // Truncation, version values, and total/declaration sizes must not produce a usable reference.
    for (std::size_t size = 0; valid.size() > size; ++size)
    {
        malformed.push_back(valid.substr(0, size));
    }

    unsupported_bodies.push_back(BoundReference("os", "name", "", spki, 0));
    unsupported_bodies.push_back(BoundReference("os", "name", "", spki, 2));
    malformed.push_back(BoundReference("os", "name", "", spki, -1));
    malformed.emplace_back("\x30\x84\x7f\xff\xff\xff", 6);
    malformed.push_back(valid + "trailing");
    malformed.push_back(valid + valid);
    malformed.push_back(std::string(4097, 'x'));
    malformed.push_back(std::string(10000, 'x'));

    // Location fields reject empty required values, excess length, and embedded control characters.
    malformed.push_back(BoundReference("", "name", "", spki));
    malformed.push_back(BoundReference("os", "", "", spki));
    malformed.push_back(BoundReference(std::string(65, 'x'), "name", "", spki));
    malformed.push_back(BoundReference("os", std::string(65, 'x'), "", spki));
    malformed.push_back(BoundReference("yubikey", "name", std::string(257, '1'), spki));
    malformed.push_back(BoundReference("os", "a\0b"sv, "", spki));
    malformed.push_back(BoundReference("os", "a\nb", "", spki));
    malformed.push_back(BoundReference("os", "name", "1\0ignored"sv, spki));

    // A reference requires a complete, valid public key.
    malformed.push_back(BoundReference("os", "name", "", ""));
    malformed.push_back(BoundReference("os", "name", "", spki.substr(0, spki.size() - 1)));
    malformed.push_back(BoundReference("os", "name", "", spki + "trailing"));
    std::string invalid_public = spki;
    ASSERT_LE(64U, invalid_public.size());
    invalid_public.replace(invalid_public.size() - 64, 64, 64, '\0');
    malformed.push_back(BoundReference("os", "name", "", invalid_public));

    // Exercise ASN.1 tag, field order, optional-field presence, and duplicate-field rules.
    const std::string prefix = DerInteger(1) + DerValue(V_ASN1_UTF8STRING, "os") + DerValue(V_ASN1_UTF8STRING, "name");
    const std::string device = DerValue(0, DerValue(V_ASN1_UTF8STRING, "123"), true, V_ASN1_CONTEXT_SPECIFIC);
    malformed.push_back(DerValue(V_ASN1_SEQUENCE, prefix + device + device + spki, true));
    malformed.push_back(DerValue(V_ASN1_SEQUENCE, prefix + spki + DerInteger(42), true));
    malformed.push_back(DerValue(V_ASN1_SEQUENCE, prefix + spki + device, true));
    malformed.push_back(DerValue(V_ASN1_SEQUENCE, prefix + DerValue(V_ASN1_OCTET_STRING, spki), true));
    malformed.push_back(
        DerValue(V_ASN1_SEQUENCE,
                 prefix + DerValue(0, DerValue(V_ASN1_UTF8STRING, ""), true, V_ASN1_CONTEXT_SPECIFIC) + spki, true));
    malformed.push_back(DerValue(
        V_ASN1_SEQUENCE,
        DerInteger(1) + DerValue(V_ASN1_OCTET_STRING, "os") + DerValue(V_ASN1_UTF8STRING, "name") + spki, true));
    malformed.push_back(DerValue(V_ASN1_SEQUENCE,
                                 DerValue(V_ASN1_INTEGER, "\x01\0\0\0\0\0\0\0\0"sv) +
                                     DerValue(V_ASN1_UTF8STRING, "os") + DerValue(V_ASN1_UTF8STRING, "name") + spki,
                                 true));

    // BER and overlong length encodings must not be accepted as canonical DER.
    const std::string fields = prefix + spki;
    malformed.push_back(std::string{"\x30\x80", 2} + fields + std::string(2, '\0')); // BER indefinite length.
    ASSERT_LT(fields.size(), 256U);
    std::string nonminimal{"\x30\x82\0", 3};
    nonminimal.push_back(static_cast<char>(fields.size()));
    malformed.push_back(nonminimal + fields);

    // Internal locator requests and unrelated binary envelopes are not persisted key references.
    malformed.push_back(InternalLocatorReference("os", "name", false));
    malformed.push_back(InternalLocatorReference("", "name", true));
    malformed.push_back(InternalLocatorReference("yubikey", "name", true));
    malformed.push_back(std::string{"MPSS-REF\0\0", 10} + std::string(28, '\0'));

    // Valid ASN.1 with unsupported algorithms or parameter forms uses a different error category.
    const evp_pkey_ptr unsupported(EVP_PKEY_Q_keygen(libctx, "provider=default", "ED25519"));
    ASSERT_NE(nullptr, unsupported);
    unsupported_bodies.push_back(BoundReference("os", "name", "", PublicKeyDer(unsupported.get())));
    ASSERT_EQ(1, EVP_PKEY_set_utf8_string_param(public_key.get(), OSSL_PKEY_PARAM_EC_ENCODING,
                                                OSSL_PKEY_EC_ENCODING_EXPLICIT));
    unsupported_bodies.push_back(BoundReference("os", "name", "", PublicKeyDer(public_key.get())));

    for (std::size_t i = 0; malformed.size() > i; ++i)
    {
        SCOPED_TRACE(i);
        ERR_clear_error();
        EXPECT_EQ(nullptr, DecodeReferencePem(libctx, ReferencePem(Base64(malformed[i]))).get());
        bool bad_encoding = false;
        for (unsigned long error = ERR_get_error(); 0 != error; error = ERR_get_error())
        {
            bad_encoding |= ERR_LIB_PROV == ERR_GET_LIB(error) && PROV_R_BAD_ENCODING == ERR_GET_REASON(error);
        }
        EXPECT_TRUE(bad_encoding);
    }

    for (const auto &body : unsupported_bodies)
    {
        ERR_clear_error();
        EXPECT_EQ(nullptr, DecodeReferencePem(libctx, ReferencePem(Base64(body))).get());
        bool not_supported = false;
        for (unsigned long error = ERR_get_error(); 0 != error; error = ERR_get_error())
        {
            not_supported |= ERR_LIB_PROV == ERR_GET_LIB(error) && PROV_R_NOT_SUPPORTED == ERR_GET_REASON(error);
        }
        EXPECT_TRUE(not_supported);
    }
}

TEST_F(MPSSStore, ForeignPrivatePemContinuesDecoderChain)
{
    const evp_pkey_ptr key(EVP_PKEY_Q_keygen(libctx, "provider=default", "EC", SN_X9_62_prime256v1));
    ASSERT_NE(nullptr, key);
    const bio_ptr pem(BIO_new(BIO_s_mem()));
    ASSERT_NE(nullptr, pem);
    ASSERT_EQ(1, PEM_write_bio_PrivateKey(pem.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr));
    const evp_pkey_ptr decoded(PEM_read_bio_PrivateKey_ex(pem.get(), nullptr, nullptr, nullptr, libctx, nullptr));
    ASSERT_NE(nullptr, decoded);
    EXPECT_EQ(1, EVP_PKEY_eq(key.get(), decoded.get()));
    EXPECT_STREQ("default", OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(decoded.get())));
}

TEST_F(MPSSStore, BoundReferenceRejectsUnknownBackendAndInvalidDevice)
{
    const evp_pkey_ptr public_key(EVP_PKEY_Q_keygen(libctx, "provider=default", "EC", SN_X9_62_prime256v1));
    ASSERT_NE(nullptr, public_key);
    const std::string spki = PublicKeyDer(public_key.get());
    ASSERT_FALSE(spki.empty());
    for (const auto &[backend, device] :
         {std::pair{"unknown-backend", ""}, std::pair{"os", "1"}, std::pair{"yubikey", "not-a-device"},
          std::pair{"yubikey", "0"}, std::pair{"yubikey", "4294967296"}})
    {
        SCOPED_TRACE(backend);
        SCOPED_TRACE(device);
        const std::string body = BoundReference(backend, "mpss_bound_invalid_location", device, spki);
        EXPECT_EQ(nullptr, DecodeReferencePem(libctx, ReferencePem(Base64(body))).get());
    }
    ERR_clear_error();
}

TEST_F(MPSSStore, DeviceParameterRejectsInvalidLocations)
{
    const std::string name = test_key_name("mpss_invalid_device");
    EXPECT_EQ(nullptr, GenerateKey(libctx, name, "os", MPSS_KEY_POLICY_NONE, "1"));
    EXPECT_EQ(nullptr, evp_pkey_ptr(store_open_key(name, "os", "1")));
    EXPECT_EQ(0, store_delete_key(name, "os", "1"));
    EXPECT_EQ(nullptr, GenerateKey(libctx, name, "unknown-backend", MPSS_KEY_POLICY_NONE, ""));
    EXPECT_EQ(nullptr, evp_pkey_ptr(store_open_key(name, "unknown-backend", "")));
    EXPECT_EQ(0, store_delete_key(name, "unknown-backend", ""));

    // Invalid C API input must report its own error, even when a different failure preceded it.
    mpss_clear_error();
    EXPECT_FALSE(mpss_delete_key_at(nullptr));
    EXPECT_TRUE(mpss_has_error());
    const std::string null_location_error = mpss::get_error();
    EXPECT_NE(std::string::npos, null_location_error.find("Invalid key name"));
    EXPECT_FALSE(mpss_is_algorithm_available("unsupported-algorithm"));
    ASSERT_NE(null_location_error, mpss::get_error());
    EXPECT_FALSE(mpss_delete_key_at(nullptr));
    EXPECT_EQ(null_location_error, mpss::get_error());

    for (const mpss_key_location_t location :
         {mpss_key_location_t{nullptr, name.c_str(), nullptr}, mpss_key_location_t{"os", nullptr, nullptr},
          mpss_key_location_t{"os", name.c_str(), ""}, mpss_key_location_t{"os", name.c_str(), "1"}})
    {
        EXPECT_FALSE(mpss_delete_key_at(&location));
    }

    // Provider parameters must also validate their type, byte length, and embedded terminators.
    const evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss"));
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx.get()));

    char embedded_nul[] = {'1', '\0', '2'};
    std::array<char, 257> oversized{};
    std::fill(oversized.begin(), oversized.end(), '1');
    int wrong_type = 1;

    for (const auto param : {OSSL_PARAM_construct_utf8_string("mpss_device_id", nullptr, 0),
                             OSSL_PARAM_construct_utf8_string("mpss_device_id", embedded_nul, sizeof(embedded_nul)),
                             OSSL_PARAM_construct_utf8_string("mpss_device_id", oversized.data(), oversized.size()),
                             OSSL_PARAM_construct_int("mpss_device_id", &wrong_type)})
    {
        const OSSL_PARAM params[]{param, OSSL_PARAM_END};
        EXPECT_EQ(0, EVP_PKEY_CTX_set_params(ctx.get(), params));
    }
    ERR_clear_error();
}

TEST_F(MPSSStore, BoundReferenceRejectsReplacementAndNeverCreates)
{
    if (!mpss_is_algorithm_available_in_backend(mpss_p256_algorithm, "os"))
    {
        GTEST_SKIP() << "Algorithm not supported by OS backend";
    }

    const std::string name = test_key_name("mpss_bound_replacement");
    const mpss_key_location_t location{"os", name.c_str(), nullptr};
    ASSERT_TRUE(mpss_delete_key_at(&location));
    SCOPE_GUARD(mpss_delete_key_at(&location));

    evp_pkey_ptr key = GenerateKey(libctx, name, "os", MPSS_KEY_POLICY_NONE, "");
    ASSERT_NE(nullptr, key);
    const std::string pem = EncodeReferencePem(key.get());
    ASSERT_FALSE(pem.empty());

    // A different public-point encoding represents the same key and must normalize to the original bytes.
    const std::string spki = PublicKeyDer(key.get());
    const auto *cursor = reinterpret_cast<const unsigned char *>(spki.data());
    const evp_pkey_ptr public_key(
        d2i_PUBKEY_ex(nullptr, &cursor, static_cast<long>(spki.size()), libctx, "provider=default"));
    ASSERT_NE(nullptr, public_key);
    ASSERT_EQ(1, EVP_PKEY_set_utf8_string_param(public_key.get(), OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED));
    const std::string equivalent = BoundReference("os", name, "", PublicKeyDer(public_key.get()));
    evp_pkey_ptr normalized = DecodeReferencePem(libctx, ReferencePem(Base64(equivalent)));
    ASSERT_NE(nullptr, normalized);
    EXPECT_EQ(spki, PublicKeyDer(normalized.get()));
    normalized.reset();

    char device[2]{};
    std::size_t written = 0;
    ASSERT_EQ(1, EVP_PKEY_get_utf8_string_param(key.get(), "mpss_device_id", device, sizeof(device), &written));
    EXPECT_STREQ("", device);

    evp_pkey_ptr opened(store_open_key(name, "os", ""));
    ASSERT_NE(nullptr, opened);
    EXPECT_EQ(PublicKeyDer(key.get()), PublicKeyDer(opened.get()));
    opened.reset();
    key.reset();
    ASSERT_EQ(1, store_delete_key(name, "os", ""));

    // A missing key is not recreated by loading its reference.
    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, pem).get());
    EXPECT_EQ(nullptr, mpss::KeyPair::Open(mpss::KeyLocation{"os", name, std::nullopt}));

    // Reusing the name must not make the saved reference accept different key material.
    key = GenerateKey(libctx, name, "os", MPSS_KEY_POLICY_NONE, "");
    ASSERT_NE(nullptr, key);
    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, pem).get());
    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, LegacyReferencePemFor("os", name)).get());
    EXPECT_NE(nullptr, DecodeReferencePem(libctx, EncodeReferencePem(key.get())).get());
}

#ifdef MPSS_BACKEND_YUBIKEY
TEST_F(MPSSStore, DeviceParameterReportsAndPersistsActualDevice)
{
    const auto devices = mpss::get_available_devices("yubikey");
    if (!devices || devices->empty())
    {
        GTEST_SKIP() << "YubiKey device not available";
    }

    const std::string device_id = devices->front();
    const std::string name = test_key_name("mpss_reference_device");
    const mpss_key_location_t location{"yubikey", name.c_str(), device_id.c_str()};
    ASSERT_TRUE(mpss_delete_key_at(&location));
    SCOPE_GUARD(mpss_delete_key_at(&location));

    evp_pkey_ptr key =
        GenerateKey(libctx, name, "yubikey", MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER | MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE,
                    device_id.c_str());
    if (!key)
    {
        GTEST_SKIP() << "YubiKey key creation unavailable: " << mpss_get_error();
    }

    std::array<char, 32> actual{};
    std::size_t written = 0;
    ASSERT_EQ(1, EVP_PKEY_get_utf8_string_param(key.get(), "mpss_device_id", actual.data(), actual.size(), &written));
    EXPECT_EQ(device_id, actual.data());

    const std::string pem = EncodeReferencePem(key.get());
    EXPECT_EQ(BoundReference("yubikey", name, device_id, PublicKeyDer(key.get())), ReferenceBody(pem));

    const evp_pkey_ptr opened(store_open_key(name, "yubikey", device_id.c_str()));
    ASSERT_NE(nullptr, opened);
    EXPECT_EQ(PublicKeyDer(key.get()), PublicKeyDer(opened.get()));

    const evp_pkey_ptr decoded = DecodeReferencePem(libctx, pem);
    ASSERT_NE(nullptr, decoded);
    EXPECT_FALSE(SignDigest(libctx, decoded.get()).empty());

    // Point the environment elsewhere; explicit locations and persisted references must keep using this device.
    const char *configured = std::getenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
    const std::optional<std::string> saved =
        nullptr == configured ? std::nullopt : std::optional<std::string>{configured};
    SCOPE_GUARD({
        if (saved)
        {
            setenv("MPSS_YUBIKEY_SERIAL", saved->c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
        else
        {
            unsetenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        }
    });

    std::uint32_t absent_serial = 1;
    while (std::ranges::find(*devices, std::to_string(absent_serial)) != devices->end())
    {
        ++absent_serial;
    }

    const std::string absent_id = std::to_string(absent_serial);
    ASSERT_EQ(0, setenv("MPSS_YUBIKEY_SERIAL", absent_id.c_str(), 1)); // NOLINT(concurrency-mt-unsafe)

    EXPECT_EQ(nullptr, evp_pkey_ptr(store_open_key(name, "yubikey")));
    EXPECT_NE(nullptr, evp_pkey_ptr(store_open_key(name, "yubikey", device_id.c_str())));
    if (1 == devices->size())
    {
        EXPECT_NE(nullptr, evp_pkey_ptr(store_open_key(name, "yubikey", "")));
    }
    EXPECT_NE(nullptr, DecodeReferencePem(libctx, pem));
    ERR_clear_error();
}
#endif

// Scenario: a persisted provider key is exported to a reference PEM and imported back.
// Expected behavior: the export matches the on-the-wire format byte for byte, and the re-imported
// key is usable for signing.
TEST_F(MPSSStore, ReferencePemEncoderCarriesNameAndRoundTrips)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = reference_fixture_key_name();
    mpss_delete_key(key_name.c_str());
    SCOPE_GUARD(mpss_delete_key(key_name.c_str()));

    evp_pkey_ptr key = GenerateKey(libctx, key_name);
    if (nullptr == key)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    // The reference pins the backend the key was opened on, even though the caller never named one,
    // so it cannot later resolve through a different default.
    const std::string pem = EncodeReferencePem(key.get());
    std::array<char, 257> device{};
    std::size_t device_size = 0;
    ASSERT_EQ(1,
              EVP_PKEY_get_utf8_string_param(key.get(), "mpss_device_id", device.data(), device.size(), &device_size));
    EXPECT_EQ(BoundReference(mpss::get_default_backend_name(), key_name, device.data(), PublicKeyDer(key.get())),
              ReferenceBody(pem));
    EXPECT_EQ(std::string::npos, pem.find("PRIVATE KEY"));

    // Cross the provider/C++ boundary in both directions without changing the serialized reference.
    const auto cpp_reference = mpss::decode_key_reference_pem(pem);
    ASSERT_TRUE(cpp_reference.has_value()) << mpss::get_error();
    auto cpp_key = mpss::KeyPair::Open(*cpp_reference);
    ASSERT_NE(nullptr, cpp_key) << mpss::get_error();
    const auto captured = cpp_key->reference();
    ASSERT_TRUE(captured.has_value()) << mpss::get_error();
    const auto cpp_pem = mpss::encode_key_reference_pem(*captured);
    ASSERT_TRUE(cpp_pem.has_value()) << mpss::get_error();
    EXPECT_EQ(pem, *cpp_pem);
    EXPECT_NE(nullptr, DecodeReferencePem(libctx, *cpp_pem));
    cpp_key.reset();

    // The encoder advertises only the private-key selection, keeping public-key material out of the
    // reference path.
    EXPECT_TRUE(EncodeReferencePem(key.get(), EVP_PKEY_PUBLIC_KEY).empty());

    key.reset();
    OSSL_LIB_CTX *application_context = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, application_context);
    SCOPE_GUARD(OSSL_LIB_CTX_free(application_context));
    ASSERT_EQ(1, EVP_set_default_properties(application_context, "provider=unavailable"));
    OSSL_LIB_CTX *previous_context = OSSL_LIB_CTX_set0_default(application_context);
    SCOPE_GUARD(OSSL_LIB_CTX_set0_default(previous_context));

    evp_pkey_ptr decoded = DecodeReferencePem(libctx, pem);
    ASSERT_NE(nullptr, decoded.get());
    EXPECT_FALSE(SignDigest(libctx, decoded.get()).empty());

    EXPECT_EQ(pem, EncodeReferencePem(decoded.get()));
}

// Scenario: a reference PEM is offered to a caller that asked for a public key.
// Expected behavior: nothing is produced. Decoding a reference opens the key it names, so the
// result can sign; a caller that asked for public material must not receive that.
TEST_F(MPSSStore, ReferencePemIsNotDecodedForAPublicKeyRequest)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = reference_fixture_key_name();
    mpss_delete_key(key_name.c_str());
    SCOPE_GUARD(mpss_delete_key(key_name.c_str()));

    evp_pkey_ptr key = GenerateKey(libctx, key_name);
    if (nullptr == key)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    const std::string pem = EncodeReferencePem(key.get());
    key.reset();

    // The same reference still loads through the private-key path.
    ASSERT_NE(nullptr, DecodeReferencePem(libctx, pem).get());

    bio_ptr in(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    ASSERT_NE(nullptr, in.get());
    const evp_pkey_ptr as_public(PEM_read_bio_PUBKEY_ex(in.get(), nullptr, nullptr, nullptr, libctx, nullptr));
    EXPECT_EQ(nullptr, as_public.get());
    ERR_clear_error();
}

// Scenario: a key created on an explicitly named backend is serialized to a reference PEM.
// Expected behavior: the reference carries that backend, so the decoder reopens the key where it
// lives instead of resolving a same-named key on the default one.
TEST_F(MPSSStore, ReferencePemCarriesExplicitBackend)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = reference_fixture_key_name();
    mpss_delete_key_from_backend(key_name.c_str(), "os");
    SCOPE_GUARD(mpss_delete_key_from_backend(key_name.c_str(), "os"));

    evp_pkey_ptr key = GenerateKey(libctx, key_name, "os");
    if (nullptr == key)
    {
        GTEST_SKIP() << "MPSS provider key generation on the os backend failed: " << mpss_get_error();
    }

    const std::string pem = EncodeReferencePem(key.get());
    EXPECT_EQ(BoundReference("os", key_name, "", PublicKeyDer(key.get())), ReferenceBody(pem));

    key.reset();
    evp_pkey_ptr decoded = DecodeReferencePem(libctx, pem);
    ASSERT_NE(nullptr, decoded.get());
    EXPECT_FALSE(SignDigest(libctx, decoded.get()).empty());
}

// Scenario: a key reopened from a reference PEM serves as a TLS server's private key.
// Expected behavior: the handshake completes. The server signs during the handshake, so completing
// one proves the reopened key signs through the provider -- the end-to-end claim the reference PEM
// exists to support, an unmodified OpenSSL consumer using a hardware key it never sees material for.
TEST_F(MPSSStore, AReferenceReloadedKeyCompletesATlsHandshake)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = reference_fixture_key_name();
    mpss_delete_key(key_name.c_str());
    SCOPE_GUARD(mpss_delete_key(key_name.c_str()));

    evp_pkey_ptr created = GenerateKey(libctx, key_name);
    if (nullptr == created)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    const std::string pem = EncodeReferencePem(created.get());
    ASSERT_FALSE(pem.empty());

    // Drop the original handle so the handshake can only be served by the reopened key.
    created.reset();

    evp_pkey_ptr server_key = DecodeReferencePem(libctx, pem);
    ASSERT_NE(nullptr, server_key.get());

    // The reopened key must belong to this provider, or the handshake below would prove nothing
    // about MPSS.
    EXPECT_EQ(mpss_prov, EVP_PKEY_get0_provider(server_key.get()));

    // A self-signed certificate over the reopened key, signed by that same key.
    const x509_ptr server_cert(X509_new_ex(libctx, nullptr));
    ASSERT_NE(nullptr, server_cert.get());
    ASSERT_EQ(1, X509_set_version(server_cert.get(), 2));
    ASSERT_EQ(1, ASN1_INTEGER_set(X509_get_serialNumber(server_cert.get()), 1));
    ASSERT_NE(nullptr, X509_gmtime_adj(X509_getm_notBefore(server_cert.get()), 0));
    ASSERT_NE(nullptr, X509_gmtime_adj(X509_getm_notAfter(server_cert.get()), 31536000L));
    ASSERT_EQ(1, X509_set_pubkey(server_cert.get(), server_key.get()));

    X509_NAME *subject = X509_get_subject_name(server_cert.get());
    ASSERT_NE(nullptr, subject);
    ASSERT_EQ(1, X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                            reinterpret_cast<const unsigned char *>("localhost"), -1, -1, 0));
    ASSERT_EQ(1, X509_set_issuer_name(server_cert.get(), subject));
    ASSERT_GT(X509_sign(server_cert.get(), server_key.get(), EVP_sha256()), 0);

    const ssl_ctx_ptr server_ctx(SSL_CTX_new_ex(libctx, nullptr, TLS_server_method()));
    ASSERT_NE(nullptr, server_ctx.get());
    ASSERT_EQ(1, SSL_CTX_use_certificate(server_ctx.get(), server_cert.get()));
    ASSERT_EQ(1, SSL_CTX_use_PrivateKey(server_ctx.get(), server_key.get()));

    const ssl_ctx_ptr client_ctx(SSL_CTX_new_ex(libctx, nullptr, TLS_client_method()));
    ASSERT_NE(nullptr, client_ctx.get());
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_PEER, nullptr);
    ASSERT_EQ(1, X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx.get()), server_cert.get()));

    const ssl_ptr server(SSL_new(server_ctx.get()));
    const ssl_ptr client(SSL_new(client_ctx.get()));
    ASSERT_NE(nullptr, server.get());
    ASSERT_NE(nullptr, client.get());
    ASSERT_EQ(1, SSL_set1_host(client.get(), "localhost"));

    // An in-memory transport, so the test needs no socket and cannot block on one.
    BIO *server_side = nullptr;
    BIO *client_side = nullptr;
    ASSERT_EQ(1, BIO_new_bio_pair(&server_side, 0, &client_side, 0));
    SSL_set_bio(server.get(), server_side, server_side);
    SSL_set_bio(client.get(), client_side, client_side);

    SSL_set_accept_state(server.get());
    SSL_set_connect_state(client.get());

    // Drive both ends until they agree or stop making progress. The bound is a guard against a
    // handshake that never settles; a healthy one needs far fewer rounds than this.
    constexpr int max_rounds = 64;
    bool client_done = false;
    bool server_done = false;
    for (int round = 0; round < max_rounds && !(client_done && server_done); ++round)
    {
        if (!client_done)
        {
            const int rc = SSL_do_handshake(client.get());
            if (1 == rc)
            {
                client_done = true;
            }
            else
            {
                const int err = SSL_get_error(client.get(), rc);
                ASSERT_TRUE(SSL_ERROR_WANT_READ == err || SSL_ERROR_WANT_WRITE == err)
                    << "client handshake failed: " << err << " (mpss: " << mpss_get_error() << ")";
            }
        }

        if (!server_done)
        {
            const int rc = SSL_do_handshake(server.get());
            if (1 == rc)
            {
                server_done = true;
            }
            else
            {
                const int err = SSL_get_error(server.get(), rc);
                ASSERT_TRUE(SSL_ERROR_WANT_READ == err || SSL_ERROR_WANT_WRITE == err)
                    << "server handshake failed: " << err << " (mpss: " << mpss_get_error() << ")";
            }
        }
    }

    ASSERT_TRUE(client_done) << "client did not finish the handshake";
    ASSERT_TRUE(server_done) << "server did not finish the handshake";
    EXPECT_EQ(X509_V_OK, SSL_get_verify_result(client.get()));
}

class CreateAndDeleteKeyTest : public ::testing::TestWithParam<const char *>
{
};

TEST_P(CreateAndDeleteKeyTest, CreateAndDeleteKey)
{
    const char *mpss_algorithm = GetParam();
    if (!mpss_is_algorithm_available(mpss_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend: " << mpss_algorithm;
    }

    std::string key_name = test_key_name("test_create_delete_key_");
    key_name.append(mpss_algorithm);

    // Delete existing key.
    const bool _ = mpss_delete_key(key_name.c_str());

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0),
                           OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(mpss_algorithm), 0),
                           OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Now delete the key using the API.
    ASSERT_EQ(1, mpss_delete_key(key_name.c_str()));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

INSTANTIATE_TEST_SUITE_P(MPSSCreateDelete, CreateAndDeleteKeyTest,
                         ::testing::Values("ECDSA with P256 and SHA2-256", "ECDSA with P384 and SHA2-384",
                                           "ECDSA with P521 and SHA2-512"),
                         [](const ::testing::TestParamInfo<const char *> &info) {
                             std::string name(info.param);
                             std::ranges::replace_if(name, [](char c) { return !std::isalnum(c); }, '_');
                             return name;
                         });

} // namespace mpss_openssl::tests

// Pins the compiler behavior the guards rely on: under MSVC's /EHsc an extern "C" function is
// assumed not to throw, so a handler outside one does not run and the process dies. Every guarded
// function therefore puts its handler inside the frame, as here.
extern "C" int mpss_test_guarded_entry(int should_throw)
try
{
    if (0 != should_throw)
    {
        throw std::runtime_error("exception at a C boundary");
    }
    return 42;
}
catch (...)
{
    return 0;
}

namespace mpss_openssl::tests
{

TEST(MPSSEntryGuard, AnExceptionAtACBoundaryReturnsFailureInsteadOfTerminating)
{
    EXPECT_EQ(42, mpss_test_guarded_entry(0));
    EXPECT_EQ(0, mpss_test_guarded_entry(1));
}

} // namespace mpss_openssl::tests
