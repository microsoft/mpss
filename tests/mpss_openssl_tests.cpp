// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <gtest/gtest.h>
#include "mpss-openssl/api.h"
#include <openssl/core.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <iostream>

namespace {
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
    TEST(MPSS_OPENSSL, OSSLTest)
    {
        const char *key_name = "test_key";
        if (mpss_is_valid_key(key_name)) {
            std::cout << "LOG: Key named " << key_name << " already exists!" << std::endl;
            bool ret = mpss_delete_key(key_name);
            std::cout << "LOG: deletion succeeded: " << ret << std::endl;
            ASSERT_EQ(1, ret);
        } else {
            std::cout << "LOG: Key named " << key_name << " does not exist. Good." << std::endl;
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

        // Check if our digest function works.
        unsigned char mpss_digest[EVP_MAX_MD_SIZE], default_digest[EVP_MAX_MD_SIZE];
        unsigned int mpss_digest_len = 0, default_digest_len = 0;
        std::string_view sample_data = "Hello world!";
        {
            EVP_MD *md = EVP_MD_fetch(mpss_libctx, "SHA256", "provider=mpss");
            ASSERT_NE(nullptr, md);

            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            ASSERT_NE(nullptr, mdctx);

            ASSERT_EQ(1, EVP_DigestInit(mdctx, md));
            ASSERT_EQ(1, EVP_DigestUpdate(mdctx, sample_data.data(), sample_data.size()));
            ASSERT_EQ(1, EVP_DigestFinal(mdctx, mpss_digest, &mpss_digest_len));

            EVP_MD_CTX_free(mdctx);
            EVP_MD_free(md);
        }
        {
            const EVP_MD *md = EVP_sha256();
            ASSERT_NE(nullptr, md);

            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            ASSERT_NE(nullptr, mdctx);

            ASSERT_EQ(1, EVP_DigestInit(mdctx, md));
            ASSERT_EQ(1, EVP_DigestUpdate(mdctx, sample_data.data(), sample_data.size()));
            ASSERT_EQ(1, EVP_DigestFinal(mdctx, default_digest, &default_digest_len));
        }

        ASSERT_EQ(mpss_digest_len, default_digest_len);
        ASSERT_TRUE(std::equal(mpss_digest, mpss_digest + mpss_digest_len, default_digest));

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
        ASSERT_GE(1, OSSL_ENCODER_CTX_get_num_encoders(ectx));

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
} // namespace mpss_openssl::tests