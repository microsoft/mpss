// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "mpss-openssl/provider/provider.h"
#ifdef MPSS_BACKEND_YUBIKEY
#include "mpss/impl/yubikey/yk_piv.h"
#endif
#include "mpss/key_policy.h"
#include "mpss/mpss.h"
#include "mpss/utils/scope_guard.h"
#include "openssl_raii.h"
#include "tests/test_key_names.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
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
            std::equal(mpss_digest, mpss_digest + mpss_digest_len, default_digest)); // NOLINT(modernize-use-ranges)
    }
};

constexpr const char *mpss_p256_algorithm = "ecdsa_secp256r1_sha256";

using mpss_openssl::testing::bio_ptr;
using mpss_openssl::testing::encoder_ctx_ptr;
using mpss_openssl::testing::evp_pkey_ctx_ptr;
using mpss_openssl::testing::evp_pkey_ptr;

// Process-unique, like every other key name in this suite, so that two test binaries running at the
// same time cannot delete each other's fixture key. A function rather than a namespace-scope string
// to keep it out of static initialization and destruction.
std::string reference_fixture_key_name()
{
    return mpss::tests::test_key_name("mpss_reference_pem_fixture");
}

// A load reference is "<backend>\0<key_name>"; an empty backend selects the default one. Built here
// rather than with the provider's builder, so the expected bytes independently pin the wire format.
std::string LoadReference(std::string_view backend, std::string_view key_name)
{
    std::string body(backend);
    body.push_back('\0');
    body.append(key_name);
    return body;
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
    if (nullptr == mem)
    {
        return {};
    }
    return {mem->data, mem->length};
}

std::string ReferencePem(std::string_view base64_body)
{
    return "-----BEGIN MPSS KEY REFERENCE-----\n" + std::string(base64_body) + "\n-----END MPSS KEY REFERENCE-----\n";
}

std::string ReferencePemFor(std::string_view backend, std::string_view key_name)
{
    return ReferencePem(Base64(LoadReference(backend, key_name)));
}

evp_pkey_ptr GenerateKey(OSSL_LIB_CTX *libctx, const std::string &key_name, const char *backend = nullptr,
                         std::uint64_t key_policy = MPSS_KEY_POLICY_NONE)
{
    evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss"));
    if (nullptr == ctx || 1 != EVP_PKEY_keygen_init(ctx.get()))
    {
        return nullptr;
    }

    OSSL_PARAM params[5];
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

} // namespace

namespace mpss_openssl::tests
{
using mpss::tests::test_key_name;

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
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });
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
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });
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
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });
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
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });

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
    char storage_desc[256] = {0};
    get_params[0] = OSSL_PARAM_construct_int("is_hardware_backed", &is_hw);
    get_params[1] = OSSL_PARAM_construct_utf8_string("storage_description", storage_desc, sizeof(storage_desc));
    get_params[2] = OSSL_PARAM_END;

    ASSERT_EQ(1, EVP_PKEY_get_params(pkey, get_params));
    // is_hardware_backed should be 0 or 1
    ASSERT_TRUE(0 == is_hw || 1 == is_hw);
    // storage_description should not be empty
    ASSERT_GT(strlen(storage_desc), 0);

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

#ifdef MPSS_BACKEND_YUBIKEY

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

#endif // MPSS_BACKEND_YUBIKEY

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
    EVP_PKEY *store_open_key(const std::string &key_name, const char *backend)
    {
        const std::string uri = "mpss:" + key_name;
        OSSL_PARAM backend_params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(nullptr != backend ? backend : ""), 0),
            OSSL_PARAM_construct_end()};
        OSSL_STORE_CTX *store = OSSL_STORE_open_ex(uri.c_str(), libctx, "provider=mpss", nullptr, nullptr,
                                                   nullptr != backend ? backend_params : nullptr, nullptr, nullptr);
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
    int store_delete_key(const std::string &key_name, const char *backend)
    {
        const std::string uri = "mpss:" + key_name;
        OSSL_PARAM backend_params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(nullptr != backend ? backend : ""), 0),
            OSSL_PARAM_construct_end()};
        return OSSL_STORE_delete(uri.c_str(), libctx, "provider=mpss", nullptr, nullptr,
                                 nullptr != backend ? backend_params : nullptr);
    }

    // Create a key (optionally on an explicit backend / with a key policy), close it, reopen it by
    // name through OSSL_STORE, and prove the reopened handle is the same key (identical SPKI) and
    // usable (its signature verifies under the default provider against the created key's public key).
    void reopen_roundtrip(const char *key_name, const char *backend, std::uint64_t key_policy)
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
TEST_F(MPSSStore, ReopenByNameYubiKey)
{
    if (mpss::impl::yubikey::YubiKeyPIV::available_serials().empty())
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
                     MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER | MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE);
}
#endif // MPSS_BACKEND_YUBIKEY

// Scenario: OpenSSL decodes an MPSS reference PEM naming a persisted key.
// Expected behavior: the key is reopened by name and is usable for signing.
TEST_F(MPSSStore, ReferencePemDecoderReopensKeyByName)
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

    evp_pkey_ptr decoded = DecodeReferencePem(libctx, ReferencePemFor("", key_name));
    ASSERT_NE(nullptr, decoded.get());
    EXPECT_FALSE(SignDigest(libctx, decoded.get()).empty());
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
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    EXPECT_EQ(nullptr, DecodeReferencePem(libctx, ReferencePem(Base64(GetParam().body))).get());
}

INSTANTIATE_TEST_SUITE_P(MalformedLoadReferences, MPSSReferencePemRejects,
                         ::testing::Values(MalformedLoadReference{"KeyDoesNotExist", "\0mpss_absent_key"sv},
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
    EXPECT_EQ(ReferencePemFor(mpss::get_default_backend_name(), key_name), pem);
    EXPECT_NE(ReferencePemFor("", key_name), pem);
    EXPECT_EQ(std::string::npos, pem.find("PRIVATE KEY"));

    // The encoder advertises only the private-key selection, keeping public-key material out of the
    // reference path.
    EXPECT_TRUE(EncodeReferencePem(key.get(), EVP_PKEY_PUBLIC_KEY).empty());

    key.reset();
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

    EXPECT_EQ(ReferencePemFor("os", key_name), EncodeReferencePem(key.get()));

    key.reset();
    evp_pkey_ptr decoded = DecodeReferencePem(libctx, ReferencePemFor("os", key_name));
    ASSERT_NE(nullptr, decoded.get());
    EXPECT_FALSE(SignDigest(libctx, decoded.get()).empty());
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
