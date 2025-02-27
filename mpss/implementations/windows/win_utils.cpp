// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/utils/utilities.h"
#include "mpss/implementations/windows/win_utils.h"
#include "mpss/implementations/windows/crypto_params.h"

#include <stdexcept>

namespace {
    // Error code of the last error that occurred.
    thread_local SECURITY_STATUS last_error = ERROR_SUCCESS;

    // Instantiating the crypto_params for each algorithm.
    constexpr mpss::impl::ECDSA_P256 ecdsa_p256;
    constexpr mpss::impl::ECDSA_P384 ecdsa_p384;
    constexpr mpss::impl::ECDSA_P521 ecdsa_p521;
}

namespace mpss::impl::utils {
    const mpss::impl::crypto_params &get_crypto_params(Algorithm algorithm)
    {
        switch (algorithm) {
        case mpss::Algorithm::ecdsa_secp256r1_sha256:
            return ecdsa_p256;
        case mpss::Algorithm::ecdsa_secp384r1_sha384:
            return ecdsa_p384;
        case mpss::Algorithm::ecdsa_secp521r1_sha512:
            return ecdsa_p521;
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
