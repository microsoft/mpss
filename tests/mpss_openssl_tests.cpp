// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <gtest/gtest.h>
#include "mpss-openssl/api.h"
#include <openssl/core.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <algorithm>
#include <random>

namespace {
    class MPSSDigest : public ::testing::Test {
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
            if (mpss_prov) {
                ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
                mpss_prov = nullptr;
            }
            if (default_prov) {
                ASSERT_NE(0, OSSL_PROVIDER_unload(default_prov));
                default_prov = nullptr;
            }
            if (mpss_libctx) {
                OSSL_LIB_CTX_free(mpss_libctx);
                mpss_libctx = nullptr;
            }
        }

        void TestDigest(const char *hash_name, const EVP_MD *(*evp_md_func)(), std::string_view in)
        {
            unsigned char mpss_digest[EVP_MAX_MD_SIZE], default_digest[EVP_MAX_MD_SIZE];
            unsigned int mpss_digest_len = 0, default_digest_len = 0;

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
            ASSERT_TRUE(std::equal(mpss_digest, mpss_digest + mpss_digest_len, default_digest));
        }
    };
} // namespace

namespace mpss_openssl::tests {
    TEST_F(MPSSDigest, SHA256)
    {
        std::random_device rd;
        for (int i = 0; i < 50; i++) {
            std::size_t size = rd() % (1024 * 1024);
            std::string input_data(size, '\0');
            std::generate(input_data.begin(), input_data.end(), [&rd]() { return static_cast<char>(rd() % 256); });
            TestDigest("SHA256", EVP_sha256, input_data);
        }
    }

    TEST_F(MPSSDigest, SHA384)
    {
        std::random_device rd;
        for (int i = 0; i < 50; i++) {
            std::size_t size = rd() % (1024 * 1024);
            std::string input_data(size, '\0');
            std::generate(input_data.begin(), input_data.end(), [&rd]() { return static_cast<char>(rd() % 256); });
            TestDigest("SHA384", EVP_sha384, input_data);
        }
    }

    TEST_F(MPSSDigest, SHA512)
    {
        std::random_device rd;
        for (int i = 0; i < 50; i++) {
            std::size_t size = rd() % (1024 * 1024);
            std::string input_data(size, '\0');
            std::generate(input_data.begin(), input_data.end(), [&rd]() { return static_cast<char>(rd() % 256); });
            TestDigest("SHA512", EVP_sha512, input_data);
        }
    }

    TEST(MPSS_OpenSSL, GetKeyDescriptors)
    {
        const char *key_name = "test_key_params";
        bool _ = mpss_delete_key(key_name);

        OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
        OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("key_name", const_cast<char *>(key_name), 0),

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
        ASSERT_TRUE(is_hw == 0 || is_hw == 1);
        // storage_description should not be empty
        ASSERT_GT(strlen(storage_desc), 0);

        EVP_PKEY_free(pkey);
        ASSERT_EQ(1, mpss_delete_key(key_name));
        ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
        OSSL_LIB_CTX_free(mpss_libctx);
    }

    class CreateAndDeleteKeyTest : public ::testing::TestWithParam<const char *> {};

    TEST_P(CreateAndDeleteKeyTest, CreateAndDeleteKey)
    {
        const char *mpss_algorithm = GetParam();
        const char *key_name = "test_create_delete_key";
        bool _ = mpss_delete_key(key_name);

        OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
        OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("key_name", const_cast<char *>(key_name), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(mpss_algorithm), 0),
            OSSL_PARAM_END};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
        EVP_PKEY *pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        // Now delete the key using the API.
        ASSERT_EQ(1, mpss_delete_key(key_name));
        ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
        OSSL_LIB_CTX_free(mpss_libctx);
    }

    INSTANTIATE_TEST_SUITE_P(
        MPSSCreateDelete,
        CreateAndDeleteKeyTest,
        ::testing::Values(
            "ECDSA with P256 and SHA2-256", "ECDSA with P384 and SHA2-384", "ECDSA with P521 and SHA2-512"));
} // namespace mpss_openssl::tests
