// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/windows/win_utils.h"

namespace {
    // Instantiating the crypto_params for each algorithm.
    constexpr mpss::impl::ECDSA_P256 ecdsa_p256;
    constexpr mpss::impl::ECDSA_P384 ecdsa_p384;
    constexpr mpss::impl::ECDSA_P521 ecdsa_p521;
}

namespace mpss::impl::utils {
    crypto_params const *const get_crypto_params(Algorithm algorithm) noexcept
    {
        switch (algorithm) {
        case mpss::Algorithm::ecdsa_secp256r1_sha256:
            return &ecdsa_p256;
        case mpss::Algorithm::ecdsa_secp384r1_sha384:
            return &ecdsa_p384;
        case mpss::Algorithm::ecdsa_secp521r1_sha512:
            return &ecdsa_p521;
        default:
            return nullptr;
        }
    }
}
