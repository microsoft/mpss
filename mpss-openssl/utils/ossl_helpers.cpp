// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/utils/memory.h"
#include "mpss-openssl/utils/names.h"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <memory>
#include <string>

#include <mpss/mpss.h>

#include <gsl/span>
#include <gsl/narrow>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/x509v3.h>

namespace mpss_openssl::utils {
    using namespace mpss;

    std::size_t mpss_sign_as_der(const std::unique_ptr<KeyPair>& key_pair, gsl::span<const std::byte> hash_tbs, gsl::span<std::byte> out)
    {
        // Check for obvious problems.
        if (!key_pair || (key_pair->algorithm() == mpss::Algorithm::unsupported)) {
            return 0;
        }

        // If out is empty, we want to only return the required size.
        if (out.empty()) {
            // This branch intentionally does not require hash_tbs to be non-empty! 

            // We need to set up an ECDSA_SIG object and create two BIGNUMs of the
            // size of the group order. Then we can call i2d_ECDSA_SIG to get the size.
            ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
            if (!ecdsa_sig) {
                std::cout << "Error: Failed to create ECDSA_SIG." << std::endl;
                return 0;
            }

            // Get the group order size. First, we need to know the NID.
            std::string group_name = try_get_ec_group(key_pair).value_or("");
            int nid = OBJ_txt2nid(group_name.c_str());
            EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
            if (!group) {
                std::cout << "Error: Failed to create EC_GROUP." << std::endl;
                ECDSA_SIG_free(ecdsa_sig);
                return 0;
            }

            // Create a BIGNUM to hold the group order.
            BIGNUM* order = BN_new();
            if (!order) {
                std::cout << "Error: Failed to create BIGNUM." << std::endl;
                EC_GROUP_free(group);
                ECDSA_SIG_free(ecdsa_sig);
                return 0;
            }
            if (1 != EC_GROUP_get_order(group, order, nullptr)) {
                std::cout << "Error: Failed to get group order." << std::endl;
                BN_free(order);
                EC_GROUP_free(group);
                ECDSA_SIG_free(ecdsa_sig);
                return 0;
            }

            // Set the signature scalars to the value of the order.
            BIGNUM* r = BN_dup(order);
            BIGNUM* s = BN_dup(order);
            if (!r || !s) {
                std::cout << "Error: Failed to duplicate BIGNUM." << std::endl;
                BN_free(order);
                EC_GROUP_free(group);
                ECDSA_SIG_free(ecdsa_sig);
                return 0;
            }

            // Set the BIGNUMs into the ECDSA_SIG object.
            if (1 != ECDSA_SIG_set0(ecdsa_sig, r, s)) {
                std::cout << "Error: ECDSA_SIG_set0 failed." << std::endl;
                BN_free(order);
                EC_GROUP_free(group);
                ECDSA_SIG_free(ecdsa_sig);
                return 0;
            }

            // Get the size of the DER encoded signature.
            int der_sig_size = i2d_ECDSA_SIG(ecdsa_sig, nullptr);
            if (der_sig_size <= 0) {
                std::cout << "Error: Failed to encode ECDSA_SIG to DER." << std::endl;
                BN_free(order);
                EC_GROUP_free(group);
                ECDSA_SIG_free(ecdsa_sig);
                return 0;
            }

            // Convert der_sig_size to std::size_t.
            std::size_t der_sig_size_sz = 0;
            try {
                der_sig_size_sz = gsl::narrow<std::size_t>(der_sig_size);
            }
            catch (const gsl::narrowing_error& e) {
                // Failed narrow. Clean up and return error.
                BN_free(order);
                EC_GROUP_free(group);
                ECDSA_SIG_free(ecdsa_sig);
                return 0;
            }

            // This is the buffer we need for the signature.
            return der_sig_size_sz;
        }

        // First try to get signature size.
        std::size_t sig_size = key_pair->sign_hash_size();
        if (0 == sig_size) {
            return 0;
        }

        // Next set up a buffer and compute the signature.
        common_byte_vector raw_sig(sig_size);
        std::size_t written = key_pair->sign_hash(hash_tbs, raw_sig);
        if (written != sig_size) {
            return 0;
        }
        std::cout << "Computed raw signature of size: " << sig_size << " bytes" << std::endl;

        // The returned signature is just two multi-word integers (r, s) concatenated.
        // We need to parse it into two BIGNUMs, write them into an OpenSSL ECDSA_SIG
        // structure, and finally encode to DER.
        const unsigned char* raw_sig_ptr =
            reinterpret_cast<const unsigned char*>(raw_sig.data());
        ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
        if (!ecdsa_sig) {
            std::cout << "Error: Failed to create ECDSA_SIG." << std::endl;
            return 0;
        }

        // Sanity check: the size should be even.
        if (sig_size & 0x1) {
            std::cout << "Error: raw signature length is not even." << std::endl;
            ECDSA_SIG_free(ecdsa_sig);
            return 0;
        }

        // Set up two BIGNUMs to hold the values.
        int sig_half_size = 0;
        try {
            sig_half_size = gsl::narrow<int>(sig_size / 2);
        }
        catch (const gsl::narrowing_error& e) {
            // Failed narrow. Clean up and return error.
            ECDSA_SIG_free(ecdsa_sig);
            return 0;
        }
        BIGNUM* r = BN_bin2bn(raw_sig_ptr, sig_half_size, nullptr);
        BIGNUM* s = BN_bin2bn(raw_sig_ptr + sig_half_size, sig_half_size, nullptr);
        if (!r || !s) {
            std::cout << "Error: Failed to create BIGNUM for r or s." << std::endl;
            BN_clear_free(r);
            BN_clear_free(s);
            ECDSA_SIG_free(ecdsa_sig);
            return 0;
        }

        if (1 != ECDSA_SIG_set0(ecdsa_sig, r, s)) {
            std::cout << "Error: ECDSA_SIG_set0 failed." << std::endl;
            // Need to still release r and s manually.
            BN_clear_free(r);
            BN_clear_free(s);
            ECDSA_SIG_free(ecdsa_sig);
            return 0;
        }

        // Encode internal ECDSA_SIG representation to DER.
        unsigned char* der_sig = nullptr;
        int der_sig_size = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
        if (der_sig_size <= 0) {
            std::cout << "Error: Failed to encode ECDSA_SIG to DER." << std::endl;
            ECDSA_SIG_free(ecdsa_sig);
            return 0;
        }

        // Convert der_sig_size to std::size_t.
        std::size_t der_sig_size_sz = 0;
        try {
            der_sig_size_sz = gsl::narrow<std::size_t>(der_sig_size);
        }
        catch (const gsl::narrowing_error& e) {
            // Failed narrow. Clean up and return error.
            OPENSSL_free(der_sig);
            ECDSA_SIG_free(ecdsa_sig);
            return 0;
        }

        // Check that der_sig_size is not greater than the output buffer size.
        if (der_sig_size_sz > out.size()) {
            std::cout << "Error: DER signature size is larger than output buffer." << std::endl;
            OPENSSL_free(der_sig);
            ECDSA_SIG_free(ecdsa_sig);
            return 0;
        }

        std::transform(der_sig, der_sig + der_sig_size_sz, out.begin(), [](unsigned char c) {
            return static_cast<std::byte>(c);
            });

        // Clean up.
        OPENSSL_free(der_sig);
        ECDSA_SIG_free(ecdsa_sig);

        return der_sig_size_sz;
    }

    [[nodiscard]] bool verify_der(const std::unique_ptr<KeyPair>& key_pair, gsl::span<const std::byte> hash_tbs, gsl::span<const std::byte> der_sig)
    {
        // Check for obvious problems.
        if (!key_pair || hash_tbs.empty() || der_sig.empty()) {
            return false;
        }

        // Read the DER encoded signature into an ECDSA_SIG struct.
        const unsigned char* der_sig_uchar_ptr =
            reinterpret_cast<const unsigned char*>(der_sig.data());
        ECDSA_SIG* ecdsa_sig = d2i_ECDSA_SIG(nullptr, &der_sig_uchar_ptr, der_sig.size());
        if (!ecdsa_sig) {
            std::cout << "Error: Failed to convert DER to ECDSA_SIG." << std::endl;
            return false;
        }

        // Extract the BIGNUMs from the ECDSA_SIG.
        BIGNUM const* r = nullptr;
        BIGNUM const* s = nullptr;
        ECDSA_SIG_get0(ecdsa_sig, &r, &s);

        // How many bytes do we need to write r and s into the buffer?
        int r_size = BN_num_bytes(r);
        int s_size = BN_num_bytes(s);
        std::size_t raw_sig_size = 0;
        try {
            raw_sig_size = gsl::narrow<std::size_t>(r_size + s_size);
        }
        catch (const gsl::narrowing_error& e) {
            // Failed narrow. Clean up and return error.
            ECDSA_SIG_free(ecdsa_sig);
            return false;
        }

        // Allocate a byte buffer to hold the raw signature.
        common_byte_vector raw_sig(raw_sig_size);

        // Write r and s into raw_sig.
        int r_size_written = BN_bn2bin(r, reinterpret_cast<unsigned char*>(raw_sig.data()));
        int s_size_written = BN_bn2bin(s, reinterpret_cast<unsigned char*>(raw_sig.data()) + r_size);
        if ((r_size_written != r_size) || (s_size_written != s_size)) {
            std::cout << "Error: Failed to convert r and s to raw signature." << std::endl;
            ECDSA_SIG_free(ecdsa_sig);
            return false;
        }

        // Finally verify the signature using mpss.
        bool res = key_pair->verify(hash_tbs, raw_sig);
        if (!res) {
            std::cout << "Error: Failed to verify raw signature." << std::endl;
        }

        // Clean up ECDSA_SIG.
        ECDSA_SIG_free(ecdsa_sig);

        return res;
    }

    [[nodiscard]] common_byte_vector mpss_vk_params_to_spki(OSSL_LIB_CTX* libctx, const OSSL_PARAM* params) {
        if (!params) {
            return {};
        }

        // Check that we have both parameters.
        const OSSL_PARAM* group = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        const OSSL_PARAM* pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (!group || !pub) {
            return {};
        }

        // Set up our own clone of the parameters to ensure nothing unexpected is passed
        // to the EVP_PKEY_fromdata function.
        OSSL_PARAM params_clone[3]{
            *group,
            *pub,
            OSSL_PARAM_END
        };

        // Create a new EVP_PKEY from the parameters.
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=default");
        if (1 != EVP_PKEY_fromdata_init(ctx)) {
            EVP_PKEY_CTX_free(ctx);
            return {};
        }
        EVP_PKEY* pkey = nullptr;
        if (1 != EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY, params_clone)) {
            EVP_PKEY_CTX_free(ctx);
            return {};
        }

        // Now encode pkey to DER using i2d_PUBKEY.
        unsigned char* der_buf = nullptr;
        int der_size = i2d_PUBKEY(pkey, &der_buf);
        if (der_size <= 0) {
            EVP_PKEY_free(pkey);
            return {};
        }
        common_byte_vector der_data(der_size);
        std::transform(der_buf, der_buf + der_size, der_data.begin(), [](unsigned char c) {
            return static_cast<std::byte>(c);
            });

        // Clean up.
        OPENSSL_free(der_buf);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return der_data;
    }
}