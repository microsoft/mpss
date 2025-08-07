// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/utils/names.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/x509v3.h>
#include <gsl/narrow>
#include <gsl/span>
#include <algorithm>
#include <cstddef>
#include <iostream>
#include <memory>
#include <mpss/mpss.h>

namespace mpss_openssl::utils {
    using namespace mpss;

    std::size_t mpss_sign_as_der(
        const std::unique_ptr<KeyPair> &key_pair, gsl::span<const std::byte> hash_tbs, gsl::span<std::byte> out)
    {
        // Check for obvious problems.
        if (!key_pair || (key_pair->algorithm() == mpss::Algorithm::unsupported)) {
            return 0;
        }

        std::size_t signature_size = key_pair->sign_hash_size();

        // If out is empty, we want to only return the required size.
        if (out.empty()) {
            // This branch intentionally does not require hash_tbs to be non-empty!
            return signature_size;
        }

        // Check that signature_size is not greater than the output buffer size.
        if (signature_size > out.size()) {
            std::cout << "Error: DER signature size is larger than output buffer." << std::endl;
            return 0;
        }

        // Compute the signature. The returned signature is ASN.1 DER encoded.
        std::size_t written = key_pair->sign_hash(hash_tbs, out);

        return written;
    }

    [[nodiscard]] bool verify_der(
        const std::unique_ptr<KeyPair> &key_pair,
        gsl::span<const std::byte> hash_tbs,
        gsl::span<const std::byte> der_sig)
    {
        // Check for obvious problems.
        if (!key_pair || hash_tbs.empty() || der_sig.empty()) {
            return false;
        }

        // Verify the signature using mpss.
        bool res = key_pair->verify(hash_tbs, der_sig);
        if (!res) {
            std::cout << "Error: Failed to verify raw signature." << std::endl;
        }

        return res;
    }

    [[nodiscard]] byte_vector mpss_vk_params_to_spki(OSSL_LIB_CTX *libctx, const OSSL_PARAM *params)
    {
        if (!params) {
            return {};
        }

        // Check that we have both parameters.
        const OSSL_PARAM *group = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        const OSSL_PARAM *pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (!group || !pub) {
            return {};
        }

        // Set up our own clone of the parameters to ensure nothing unexpected is passed
        // to the EVP_PKEY_fromdata function.
        OSSL_PARAM params_clone[3]{*group, *pub, OSSL_PARAM_END};

        // Create a new EVP_PKEY from the parameters.
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=default");
        if (1 != EVP_PKEY_fromdata_init(ctx)) {
            EVP_PKEY_CTX_free(ctx);
            return {};
        }
        EVP_PKEY *pkey = nullptr;
        if (1 != EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY, params_clone)) {
            EVP_PKEY_CTX_free(ctx);
            return {};
        }

        // Now encode pkey to DER using i2d_PUBKEY.
        unsigned char *der_buf = nullptr;
        int der_size = i2d_PUBKEY(pkey, &der_buf);
        if (der_size <= 0) {
            EVP_PKEY_free(pkey);
            return {};
        }
        byte_vector der_data(der_size);
        std::transform(
            der_buf, der_buf + der_size, der_data.begin(), [](unsigned char c) { return static_cast<std::byte>(c); });

        // Clean up.
        OPENSSL_free(der_buf);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return der_data;
    }
} // namespace mpss_openssl::utils
