// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <gtest/gtest.h>
#include "mpss-openssl/api.h"
#include "mpss-openssl/utils/utils.h"
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <filesystem>

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
    class CertificateChainSerializationTest : public ::testing::TestWithParam<const char *> {};

    /** This comprehensive test demonstrates a complete workflow as follows:
     *
     *    1. Create a new key pair in a secure environment.
     *    2. Generate a self-signed (CA) certificate for the public key.
     *    3. Create an independent RSA key pair outside the secure environment.
     *    4. Sign the EE certificate with the CA certificate's secret key.
     *    5. Serialize both certificates and the CA public key in PEM format.
     *    6. Load all three objects back into the OpenSSL default provider.
     *    7. Check that the cert chain verifies with the OpenSSL default provider.
     *    8. Clean up the OpenSSL resources and delete the mpss secret key.
     * ----------------------------------------------------------------------------------- */
    TEST_P(CertificateChainSerializationTest, CertificateChainSerialization)
    {
        const char *mpss_algorithm = GetParam();
        std::string ca_key_name = std::string("test_ca_key_") + mpss_algorithm;

        // We delete the key (by its name) to clean up a leftover key that may have been left
        // by an early terminated run of this test. The function returns whether or not the
        // key was successfully deleted (for example, it fails if no such key is present in
        // the secure environment).
        bool deleted = mpss_delete_key(ca_key_name.c_str());

        // To read the last (thread-local) error from mpss core, use mpss_get_error.
        if (deleted) {
            const char *error_msg = mpss_get_error();
            ASSERT_NE(nullptr, error_msg);
        }

        OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);

        // Built‑in algorithms (ASN.1 encoder/decoder, RSA, etc.)
        OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(mpss_libctx, "default");
        ASSERT_NE(nullptr, default_prov);

        // Register our out‑of‑tree provider with the core *before* loading it.
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));

        // Load the provider; afterwards algorithm names like "ec" with "provider=mpss"
        // property query resolve to these implementations.
        OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);

        // -------------------------------------------------------------------------
        // 1.  Create a new key pair in a secure environment.
        // -------------------------------------------------------------------------
        EVP_PKEY_CTX *ca_ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ca_ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ca_ctx));

        // Pass provider‑specific parameters: give the key a persistent name and tell
        // the provider what concrete algorithm suite we want.
        //
        // The "key_name" indicates a name identifier under which the key is stored in the
        // local secure environment. Only one key with a specific name can be stored at one
        // time. We recommend descriptive names that you can easily identify later. Attempting
        // to create a key with a duplicate name, or to open a key that is already opened,
        // will result in an error.
        //
        // The "mpss_algorithm" must be one of
        //
        //  { "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512" }
        //
        // although there is some flexibility here. For example, "ecdsa-p256-sha2-256"
        // would be parsed correctly and ends up equivalent to "ecdsa_secp256r1_sha256".
        // See mpss-openssl/utils/names.h|.cpp for different valid algorithm identifiers.
        OSSL_PARAM ca_params[] = {
            OSSL_PARAM_construct_utf8_string("key_name", const_cast<char *>(ca_key_name.c_str()), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(mpss_algorithm), 0),
            OSSL_PARAM_END};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ca_ctx, ca_params));

        // Create the ECDSA key pair in the local secure environment.
        EVP_PKEY *ca_pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_generate(ca_ctx, &ca_pkey));
        EVP_PKEY_CTX_free(ca_ctx);

        // -------------------------------------------------------------------------
        // 2. Generate a self-signed (CA) certificate for the public key.
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

        // Sign with the CA key. We use an internal API here to extract the correct hash
        // function name for this test. In practice, the user would know what hash function
        // they need to use.
        std::string_view hash_name = mpss_openssl::utils::get_canonical_hash_name(mpss_algorithm);
        const EVP_MD *hash_func = EVP_get_digestbyname(hash_name.data());
        ASSERT_GT(X509_sign(ca_cert, ca_pkey, hash_func), 0);

        // -------------------------------------------------------------------------
        // 3. Create an independent RSA key pair outside the secure environment.
        // -------------------------------------------------------------------------
        EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "RSA", nullptr /* default provider */);
        ASSERT_NE(nullptr, rsa_ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(rsa_ctx));
        ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 3072));

        EVP_PKEY *rsa_pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_keygen(rsa_ctx, &rsa_pkey));
        EVP_PKEY_CTX_free(rsa_ctx);

        // -------------------------------------------------------------------------
        // 4. Sign the EE certificate with the CA certificate's secret key.
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

        // Quick verification before we serialize anything. These are verified by
        // the mpss provider itself. In fact, the verification happens in the secure
        // environment, which is obviously not necessary, as verification is a public
        // operation.
        ASSERT_EQ(1, X509_verify(ca_cert, ca_pkey));  // CA self‑sig
        ASSERT_EQ(1, X509_verify(end_cert, ca_pkey)); // EE signed by CA

        // -------------------------------------------------------------------------
        // 5. Serialize both certificates and the CA public key in PEM format.
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
        // 6. Load all three objects back into the OpenSSL default provider.
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
        // 7. Check that the cert chain verifies with the OpenSSL default provider.
        // -------------------------------------------------------------------------
        //
        // We can verify both certs simply against the public key.
        ASSERT_EQ(1, X509_verify(loaded_ca_cert, loaded_pubkey));
        ASSERT_EQ(1, X509_verify(loaded_end_cert, loaded_pubkey));

        // We can also build a certificate store and verify that way.
        X509_STORE *store = X509_STORE_new();
        ASSERT_NE(nullptr, store);
        ASSERT_EQ(1, X509_STORE_add_cert(store, loaded_ca_cert));

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        ASSERT_NE(nullptr, ctx);

        // Initialize the verification context with the EE cert and CA store
        ASSERT_EQ(1, X509_STORE_CTX_init(ctx, store, loaded_end_cert, NULL));

        // Actually verify the chain
        ASSERT_EQ(1, X509_verify_cert(ctx));

        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);

        // -------------------------------------------------------------------------
        // 8. Clean up the OpenSSL resources and delete the mpss secret key.
        // -------------------------------------------------------------------------
        ASSERT_TRUE(std::filesystem::remove("test_ca.pem"));
        ASSERT_TRUE(std::filesystem::remove("test_end_cert.pem"));
        ASSERT_TRUE(std::filesystem::remove("test_ca_pubkey.pem"));

        X509_free(ca_cert);
        X509_free(end_cert);
        X509_free(loaded_ca_cert);
        X509_free(loaded_end_cert);

        EVP_PKEY_free(ca_pkey);

        // Delete the mpss private (and public) key!
        ASSERT_EQ(1, mpss_delete_key(ca_key_name.c_str()));

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
} // namespace mpss_openssl::tests
