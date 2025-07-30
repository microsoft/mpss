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
#include <openssl/x509v3.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
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

    //TEST(MPSS_OPENSSL, DigestTest)
    //{
    //    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    //    ASSERT_NE(nullptr, mpss_libctx);

    //    // Register and load the mpss provider and default provider.
    //    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    //    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    //    ASSERT_NE(nullptr, mpss_prov);
    //    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(mpss_libctx, "default");
    //    ASSERT_NE(nullptr, default_prov);

    //    // Check if our digest function works. This is a lambda that takes the hash function
    //    // name (e.g., "SHA256") and the OpenSSL EVP method that returns an EVP_MD pointer.
    //    // It hashes a bunch of random input and checks that both hash functions give the
    //    // same output.
    //    auto test_digest = [&](const char *hash_name, const EVP_MD *(*evp_md_func)(), std::string_view in) {
    //        unsigned char mpss_digest[EVP_MAX_MD_SIZE], default_digest[EVP_MAX_MD_SIZE];
    //        unsigned int mpss_digest_len = 0, default_digest_len = 0;

    //        EVP_MD *md = EVP_MD_fetch(mpss_libctx, hash_name, "provider=mpss");
    //        ASSERT_NE(nullptr, md);
    //        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    //        ASSERT_NE(nullptr, mdctx);
    //        ASSERT_EQ(1, EVP_DigestInit(mdctx, md));
    //        ASSERT_EQ(1, EVP_DigestUpdate(mdctx, in.data(), in.size()));
    //        unsigned int digest_len = 0;
    //        ASSERT_EQ(1, EVP_DigestFinal(mdctx, mpss_digest, &digest_len));
    //        mpss_digest_len = digest_len;
    //        EVP_MD_CTX_free(mdctx);
    //        mdctx = nullptr;
    //        EVP_MD_free(md);
    //        md = nullptr;

    //        const EVP_MD *default_md = evp_md_func();
    //        ASSERT_NE(nullptr, default_md);
    //        mdctx = EVP_MD_CTX_new();
    //        ASSERT_NE(nullptr, mdctx);
    //        ASSERT_EQ(1, EVP_DigestInit(mdctx, default_md));
    //        ASSERT_EQ(1, EVP_DigestUpdate(mdctx, in.data(), in.size()));
    //        ASSERT_EQ(1, EVP_DigestFinal(mdctx, default_digest, &default_digest_len));
    //        EVP_MD_CTX_free(mdctx);
    //        mdctx = nullptr;

    //        // Check equality.
    //        ASSERT_EQ(mpss_digest_len, default_digest_len);
    //        ASSERT_TRUE(std::equal(mpss_digest, mpss_digest + mpss_digest_len, default_digest));
    //    };

    //    std::random_device rd;

    //    // Test the digest functions with different random inputs.
    //    for (int i = 0; i < 50; i++) {
    //        // Choose a random size up to 1MB.
    //        std::size_t size = rd() % (1024 * 1024);

    //        // Generate random input data.
    //        std::string input_data(size, '\0');
    //        std::generate(input_data.begin(), input_data.end(), [&rd]() { return static_cast<char>(rd() % 256); });
    //        test_digest("SHA256", EVP_sha256, input_data);
    //        test_digest("SHA384", EVP_sha384, input_data);
    //        test_digest("SHA512", EVP_sha512, input_data);
    //    }

    //    // Unload the providers and the library context.
    //    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    //    ASSERT_NE(0, OSSL_PROVIDER_unload(default_prov));
    //    OSSL_LIB_CTX_free(mpss_libctx);
    //}

    TEST(MPSS_OPENSSL, OSSLTest)
    {
        const char *key_name = "test_key";
        if (mpss_is_valid_key(key_name)) {
            bool ret = mpss_delete_key(key_name);
            ASSERT_EQ(1, ret);
        }

        OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);

        // We also need the default provider for RSA.
        OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(mpss_libctx, "default");
        ASSERT_NE(nullptr, default_prov);

        // Register the mpss provider.
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));

        // Load our provider.
        OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);

        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));

        // Now set the parameters to use ECDSA-P256-SHA256.
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("key_name", const_cast<char *>(key_name), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
            OSSL_PARAM_END};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));

        // Generate the key.
        EVP_PKEY *pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));

        // We can free the ctx now before creating a context for signing.
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new_from_pkey(mpss_libctx, pkey, "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(1, EVP_PKEY_sign_init(ctx));

        // Set a fixed  buffer that is 256 characters long. All repeated 'A'.
        std::vector<unsigned char> tbs(256 / 8, 'A');
        std::size_t tbs_len = tbs.size();
        std::vector<unsigned char> signature;
        std::size_t signature_len = 0;

        // This obtains the size bound on the signature.
        ASSERT_EQ(1, EVP_PKEY_sign(ctx, nullptr, &signature_len, tbs.data(), tbs_len));
        signature.resize(signature_len);

        // Actually sign.
        ASSERT_EQ(1, EVP_PKEY_sign(ctx, signature.data(), &signature_len, tbs.data(), tbs_len));
        signature.resize(signature_len);

        // Next we set up the context to verify.
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(mpss_libctx, pkey, "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(1, EVP_PKEY_verify_init(ctx));
        ASSERT_EQ(1, EVP_PKEY_verify(ctx, signature.data(), signature_len, tbs.data(), tbs_len));

        // Next try to extract the public key from EVP_PKEY.
        std::vector<unsigned char> public_key;
        std::size_t public_key_len = 1024;
        public_key.resize(public_key_len);
        ASSERT_EQ(1, EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &public_key_len));
        public_key.resize(public_key_len);
        ASSERT_EQ(public_key_len, 65);

        // Set up the encoder for SPKI/DER.
        OSSL_ENCODER_CTX *ectx =
            OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", "provider=mpss");
        ASSERT_NE(nullptr, ectx);

        // We should find at least our DER encoder.
        ASSERT_GE(OSSL_ENCODER_CTX_get_num_encoders(ectx), 1);

        // Now try getting the public key.
        unsigned char *spki_der = nullptr;
        std::size_t spki_der_len = 0;
        ASSERT_EQ(1, OSSL_ENCODER_to_data(ectx, &spki_der, &spki_der_len));

        // Create X509 cert.
        X509 *cert = X509_new_ex(mpss_libctx, "provider=mpss");
        ASSERT_NE(nullptr, cert);

        // Set properties and the public key.
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
        ASSERT_NE(0, X509_set_pubkey(cert, pkey));

        // Set the subject name.
        X509_NAME *sname = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(sname, "C", MBSTRING_ASC, (const unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(sname, "O", MBSTRING_ASC, (const unsigned char *)"Test", -1, -1, 0);
        X509_NAME_add_entry_by_txt(sname, "CN", MBSTRING_ASC, (const unsigned char *)"Test", -1, -1, 0);
        ASSERT_NE(0, X509_set_issuer_name(cert, sname));

        // Make this a CA cert.
        add_ca_extensions(cert);

        // Sign the cert with the private key.
        int sigsize = X509_sign(cert, pkey, EVP_sha256());
        ASSERT_GT(sigsize, 0);

        // Verify the cert.
        ASSERT_EQ(1, X509_verify(cert, pkey));

        // Now, create another random RSA key and a certificate, and sign it with our cert.

        // Set up RSA key.
        EVP_PKEY_CTX *pctx = nullptr;
        pctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "RSA", nullptr);
        ASSERT_NE(nullptr, pctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(pctx));
        ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 3072));
        EVP_PKEY *rsa_pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_keygen(pctx, &rsa_pkey));
        EVP_PKEY_CTX_free(pctx);

        // Create the sub cert.
        X509 *sub_cert = nullptr;
        sub_cert = X509_new_ex(mpss_libctx, "provider=mpss");
        X509_set_version(sub_cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(sub_cert), 1);
        X509_gmtime_adj(X509_get_notBefore(sub_cert), 0);
        X509_gmtime_adj(X509_get_notAfter(sub_cert), 31536000L);
        ASSERT_NE(0, X509_set_pubkey(sub_cert, rsa_pkey));
        X509_NAME *sname2 = X509_get_subject_name(sub_cert);
        X509_NAME_add_entry_by_txt(sname2, "C", MBSTRING_ASC, (const unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(sname2, "O", MBSTRING_ASC, (const unsigned char *)"Test RSA", -1, -1, 0);
        X509_NAME_add_entry_by_txt(sname2, "CN", MBSTRING_ASC, (const unsigned char *)"Test RSA", -1, -1, 0);
        ASSERT_NE(0, X509_set_issuer_name(sub_cert, sname));

        // Sign with our cert.
        ASSERT_GT(X509_sign(sub_cert, pkey, EVP_sha256()), 0);

        // Verify that the cert is valid.
        ASSERT_EQ(1, X509_verify(sub_cert, pkey));

        // Clean up.
        X509_free(cert);
        X509_free(sub_cert);
        EVP_PKEY_free(pkey);
        OSSL_ENCODER_CTX_free(ectx);
        EVP_PKEY_CTX_free(ctx);

        // Unload the provider.
        ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));

        // Unload the default provider.
        ASSERT_NE(0, OSSL_PROVIDER_unload(default_prov));

        // Unload the library context.
        OSSL_LIB_CTX_free(mpss_libctx);
    }

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

    TEST(MPSS_OPENSSL, CertificateChainSerialization)
    {
        // -------------------------------------------------------------------------
        // 0.  Make sure we start with a clean slate in the mpss provider’s storage
        //     (the provider may persist keys under a human‑readable name).
        // -------------------------------------------------------------------------
        const char *ca_key_name = "test_ca_key";

        if (mpss_is_valid_key(ca_key_name)) {        // If a key with that
            bool ret = mpss_delete_key(ca_key_name); // name already exists,
            ASSERT_EQ(1, ret);                       // delete it.
        }

        // -------------------------------------------------------------------------
        // 1.  Create an explicit OpenSSL library context and load providers.
        // -------------------------------------------------------------------------
        OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new(); // Independent “world”
        ASSERT_NE(nullptr, mpss_libctx);                // for this test.

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
            OSSL_PARAM_construct_utf8_string("key_name", const_cast<char *>(ca_key_name), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
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
        ASSERT_GT(X509_sign(ca_cert, ca_pkey, EVP_sha256()), 0);

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
        ASSERT_GT(X509_sign(end_cert, ca_pkey, EVP_sha256()), 0);

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
} // namespace mpss_openssl::tests