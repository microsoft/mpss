// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/utils/utilities.h"
#include "win_utils.h"
#include "ecdsa_p256.h"
#include "ecdsa_p384.h"
#include "ecdsa_p521.h"



namespace {
    // Error code of the last error that occurred.
    thread_local SECURITY_STATUS last_error = ERROR_SUCCESS;

    // Different implementations of crypto parameters
    mpss::impl::ecdsa_p256 p256_crypto_params;
    mpss::impl::ecdsa_p384 p384_crypto_params;
    mpss::impl::ecdsa_p521 p521_crypto_params;
}

namespace mpss {
    namespace impl {
        namespace utils {
            const crypto_params& GetCryptoParams(SignatureAlgorithm algorithm)
            {
                switch (algorithm) {
                case mpss::SignatureAlgorithm::ECDSA_P256_SHA256:
                    return p256_crypto_params;
                case mpss::SignatureAlgorithm::ECDSA_P384_SHA384:
                    return p384_crypto_params;
                case mpss::SignatureAlgorithm::ECDSA_P521_SHA512:
                    return p521_crypto_params;
                default:
                    throw std::invalid_argument("Unsupported algorithm");
                }
            }

            void set_error(SECURITY_STATUS status, std::string error)
            {
                last_error = status;
                mpss::utils::set_error(std::move(error));
            }
        }
    }
}
