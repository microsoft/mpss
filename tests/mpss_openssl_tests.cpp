// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"

#include <iostream>

#include <openssl/core.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>

#include <gtest/gtest.h>

namespace {
    int add_ca_extensions(X509* cert) {
        X509V3_CTX ctx;
        X509_EXTENSION* ext = NULL;
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
}

namespace mpss_openssl::tests {
    TEST(MPSS_OPENSSL, OSSLTest) {
        const char* key_name = "test_key";
        if (mpss_is_valid_key(key_name)) {
            std::cout << "LOG: Key named " << key_name << " already exists!" << std::endl;
            bool ret = mpss_delete_key(key_name);
            std::cout << "LOG: deletion succeeded: " << ret << std::endl;
            ASSERT_EQ(1, ret);
        }
        else {
            std::cout << "LOG: Key named " << key_name << " does not exist. Good." << std::endl;
        }

        OSSL_LIB_CTX* mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);

        // We also need the default provider for RSA.
        OSSL_PROVIDER* default_prov = OSSL_PROVIDER_load(mpss_libctx, "default");
        ASSERT_NE(nullptr, default_prov);
    }
}