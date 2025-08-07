// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <gtest/gtest.h>
#include "mpss-openssl/api.h"
#include "mpss-openssl/utils/names.h"
#include <openssl/core.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <filesystem>
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

    int add_ca_extensions(X509 *cert)
    {
        X509V3_CTX ctx;
        X509_EXTENSION *ext = NULL;
        int ret = 0;

        /*
         * Set up the extension context.
         * Parameters: issuer cert, subject cert, request, crl.
         * Since this is a self-signed cert, both issuer and subject are 'cert'.
         */
        X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

        // Add Basic Constraints: critical, CA:TRUE
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
        if (!ext)
            goto end;
        if (!X509_add_ext(cert, ext, -1))
            goto end;
        X509_EXTENSION_free(ext);
        ext = NULL;

        // Add Key Usage: critical, keyCertSign and cRLSign
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
        if (!ext)
            goto end;
        if (!X509_add_ext(cert, ext, -1))
            goto end;
        ret = 1;

    end:
        if (ext)
            X509_EXTENSION_free(ext);
        return ret;
    }
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

    // -----------------------------------------------------------------------------
    // Parameterized fixture for CertificateChainSerialization
    class CertificateChainSerializationTest : public ::testing::TestWithParam<const char *> {};

    // -----------------------------------------------------------------------------
    // This test exercises a complete “generate → sign → serialize → reload → verify”
    // workflow using OpenSSL 3’s provider model. It deliberately:
    //
    //   1. Creates its own OSSL_LIB_CTX and loads two providers into it
    //      – the built‑in “default” provider and a custom provider called “mpss”.
    //   2. Generates an *EC* key in the mpss provider and uses it as a CA key.
    //   3. Builds and self‑signs a CA certificate (X.509 v3).
    //   4. Generates an *RSA‑3072* key (default provider) for an end‑entity (EE).
    //   5. Builds an EE certificate and signs it with the CA key.
    //   6. Serializes both certs and the CA public key to PEM files, reloads them
    //      from disk, and re‑verifies all signatures.
    //   7. Cleans up every object and file it created.
    //
    // The point of the test is to prove that the whole chain can be constructed and
    // later reconstructed outside the process (filesystem boundary) without losing
    // cryptographic validity.
    // -----------------------------------------------------------------------------

    TEST_P(CertificateChainSerializationTest, CertificateChainSerialization)
    {
        const char *mpss_algorithm = GetParam();
        std::string ca_key_name = std::string("test_ca_key_") + mpss_algorithm;

        if (mpss_is_valid_key(ca_key_name.c_str())) {
            bool ret = mpss_delete_key(ca_key_name.c_str());
            ASSERT_EQ(1, ret);
        }

        OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);

        // Built‑in algorithms (ASN.1 encoder/decoder, RSA, etc.)
        OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(mpss_libctx, "default");
        ASSERT_NE(nullptr, default_prov);

        // Register our out‑of‑tree provider with the core *before* loading it.
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));

        // Load the provider; afterwards algorithm names like “ec” with
        // “provider=mpss” property query resolve to these implementations.
        OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);

        // -------------------------------------------------------------------------
        // 2.  Generate an *EC* CA key inside the mpss provider.
        // -------------------------------------------------------------------------
        // Create a key‑generation context for type “EC” resolved in mpss.
        EVP_PKEY_CTX *ca_ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ca_ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ca_ctx));

        // Pass provider‑specific parameters: give the key a persistent name and
        // tell the provider what concrete algorithm suite we want.
        OSSL_PARAM ca_params[] = {
            OSSL_PARAM_construct_utf8_string("key_name", const_cast<char *>(ca_key_name.c_str()), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(mpss_algorithm), 0),
            OSSL_PARAM_END};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ca_ctx, ca_params));

        EVP_PKEY *ca_pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_generate(ca_ctx, &ca_pkey)); // Actual key material.
        EVP_PKEY_CTX_free(ca_ctx);

        // -------------------------------------------------------------------------
        // 3.  Build and self‑sign the CA certificate.
        // -------------------------------------------------------------------------
        X509 *ca_cert = X509_new_ex(mpss_libctx, "provider=mpss");
        ASSERT_NE(nullptr, ca_cert);

        X509_set_version(ca_cert, 2);                           // v3 (zero‑based)
        ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);    // serial = 1
        X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);        // notBefore = now
        X509_gmtime_adj(X509_get_notAfter(ca_cert), 31536000L); // +365 days

        ASSERT_NE(0, X509_set_pubkey(ca_cert, ca_pkey)); // embed CA pubkey

        // Subject == Issuer (self‑signed)
        X509_NAME *ca_name = X509_get_subject_name(ca_cert);
        X509_NAME_add_entry_by_txt(ca_name, "C", MBSTRING_ASC, (const unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(ca_name, "O", MBSTRING_ASC, (const unsigned char *)"Test CA", -1, -1, 0);
        X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, (const unsigned char *)"Test CA", -1, -1, 0);
        ASSERT_NE(0, X509_set_issuer_name(ca_cert, ca_name));

        // Attach mandatory v3 CA extensions (critical BasicConstraints CA:TRUE  +  critical KeyUsage
        // keyCertSign|cRLSign)
        add_ca_extensions(ca_cert);

        // Sign with the CA key (provider chooses ECDSA+SHA‑256).
        // Use internal API here to get the correct hash function for this test.
        std::string_view hash_name = mpss_openssl::utils::get_canonical_hash_name(mpss_algorithm);
        const EVP_MD *hash_func = EVP_get_digestbyname(hash_name.data());
        ASSERT_GT(X509_sign(ca_cert, ca_pkey, hash_func), 0);

        // -------------------------------------------------------------------------
        // 4.  Generate an RSA‑3072 key (default provider) for the end‑entity.
        // -------------------------------------------------------------------------
        EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "RSA", nullptr /* default provider */);
        ASSERT_NE(nullptr, rsa_ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(rsa_ctx));
        ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 3072));

        EVP_PKEY *rsa_pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_keygen(rsa_ctx, &rsa_pkey));
        EVP_PKEY_CTX_free(rsa_ctx);

        // -------------------------------------------------------------------------
        // 5.  Build and sign the EE certificate with the CA key.
        // -------------------------------------------------------------------------
        X509 *end_cert = X509_new_ex(mpss_libctx, "provider=mpss");
        ASSERT_NE(nullptr, end_cert);

        X509_set_version(end_cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(end_cert), 2);
        X509_gmtime_adj(X509_get_notBefore(end_cert), 0);
        X509_gmtime_adj(X509_get_notAfter(end_cert), 31536000L);
        ASSERT_NE(0, X509_set_pubkey(end_cert, rsa_pkey)); // embed EE key

        // Subject
        X509_NAME *end_name = X509_get_subject_name(end_cert);
        X509_NAME_add_entry_by_txt(end_name, "C", MBSTRING_ASC, (const unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(end_name, "O", MBSTRING_ASC, (const unsigned char *)"End Entity", -1, -1, 0);
        X509_NAME_add_entry_by_txt(end_name, "CN", MBSTRING_ASC, (const unsigned char *)"test.example.com", -1, -1, 0);

        // Issuer = CA
        ASSERT_NE(0, X509_set_issuer_name(end_cert, ca_name));

        // Sign with CA key.
        ASSERT_GT(X509_sign(end_cert, ca_pkey, hash_func), 0);

        // -------------------------------------------------------------------------
        // 6.  Quick in‑memory verification before we serialize anything.
        // -------------------------------------------------------------------------
        ASSERT_EQ(1, X509_verify(ca_cert, ca_pkey));  // CA self‑sig
        ASSERT_EQ(1, X509_verify(end_cert, ca_pkey)); // EE signed by CA

        // -------------------------------------------------------------------------
        // 7.  Serialize: write both certs and the CA pubkey to PEM files.
        // -------------------------------------------------------------------------
        BIO *ca_file = BIO_new_file("test_ca.pem", "w");
        ASSERT_NE(nullptr, ca_file);
        ASSERT_EQ(1, PEM_write_bio_X509(ca_file, ca_cert));
        BIO_free(ca_file);

        BIO *end_file = BIO_new_file("test_end_cert.pem", "w");
        ASSERT_NE(nullptr, end_file);
        ASSERT_EQ(1, PEM_write_bio_X509(end_file, end_cert));
        BIO_free(end_file);

        BIO *pubkey_file = BIO_new_file("test_ca_pubkey.pem", "w");
        ASSERT_NE(nullptr, pubkey_file);
        ASSERT_EQ(1, PEM_write_bio_PUBKEY_ex(pubkey_file, ca_pkey, mpss_libctx, "provider=mpss"));
        BIO_free(pubkey_file);

        // -------------------------------------------------------------------------
        // 8.  Reload the PEM objects back into memory (default provider unless
        //     property queries are supplied).
        // -------------------------------------------------------------------------
        BIO *ca_load_bio = BIO_new_file("test_ca.pem", "r");
        ASSERT_NE(nullptr, ca_load_bio);
        X509 *loaded_ca_cert = PEM_read_bio_X509(ca_load_bio, nullptr, nullptr, nullptr);
        ASSERT_NE(nullptr, loaded_ca_cert);
        BIO_free(ca_load_bio);

        BIO *end_load_bio = BIO_new_file("test_end_cert.pem", "r");
        ASSERT_NE(nullptr, end_load_bio);
        X509 *loaded_end_cert = PEM_read_bio_X509(end_load_bio, nullptr, nullptr, nullptr);
        ASSERT_NE(nullptr, loaded_end_cert);
        BIO_free(end_load_bio);

        BIO *pubkey_load_bio = BIO_new_file("test_ca_pubkey.pem", "r");
        ASSERT_NE(nullptr, pubkey_load_bio);
        EVP_PKEY *loaded_pubkey = PEM_read_bio_PUBKEY(pubkey_load_bio, nullptr, nullptr, nullptr);
        ASSERT_NE(nullptr, loaded_pubkey);
        BIO_free(pubkey_load_bio);

        // -------------------------------------------------------------------------
        // 9.  Verify again using the *reloaded* public key.
        //     (Note: if the CA key was provider‑specific, this may fail unless the
        //     key is imported back into the same provider.)
        // -------------------------------------------------------------------------

        ASSERT_EQ(1, X509_verify(loaded_ca_cert, loaded_pubkey));
        ASSERT_EQ(1, X509_verify(loaded_end_cert, loaded_pubkey));

        // -------------------------------------------------------------------------
        // 10. House‑keeping: delete temporary files and free all OpenSSL objects.
        // -------------------------------------------------------------------------
        ASSERT_TRUE(std::filesystem::remove("test_ca.pem"));
        ASSERT_TRUE(std::filesystem::remove("test_end_cert.pem"));
        ASSERT_TRUE(std::filesystem::remove("test_ca_pubkey.pem"));

        X509_free(ca_cert);
        X509_free(end_cert);
        X509_free(loaded_ca_cert);
        X509_free(loaded_end_cert);

        EVP_PKEY_free(ca_pkey);
        EVP_PKEY_free(rsa_pkey);
        EVP_PKEY_free(loaded_pubkey);

        // Unload providers (reverse order not strictly required, but neat).
        ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
        ASSERT_NE(0, OSSL_PROVIDER_unload(default_prov));

        // Destroy the library context.
        OSSL_LIB_CTX_free(mpss_libctx);
    }

    INSTANTIATE_TEST_SUITE_P(
        MPSSCertChain,
        CertificateChainSerializationTest,
        ::testing::Values("ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512"));

    TEST(MPSS_OPENSSL, GetKeyDescriptors)
    {
        const char *key_name = "test_key_params";
        if (mpss_is_valid_key(key_name)) {
            bool ret = mpss_delete_key(key_name);
            ASSERT_EQ(1, ret);
        }

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
        ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
        OSSL_LIB_CTX_free(mpss_libctx);
    }

    class CreateAndDeleteKeyTest : public ::testing::TestWithParam<const char *> {};

    TEST_P(CreateAndDeleteKeyTest, CreateAndDeleteKey)
    {
        const char *mpss_algorithm = GetParam();
        const char *key_name = "test_create_delete_key";
        if (mpss_is_valid_key(key_name)) {
            bool ret = mpss_delete_key(key_name);
            ASSERT_EQ(1, ret);
        }

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
