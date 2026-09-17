// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/ossl_ptr.h"
#include <memory>
#include <openssl/encoder.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace mpss_openssl::testing
{

// Aliases for what the provider already declares, so the tests do not maintain a second set.
using utils::bio_ptr;
using utils::evp_pkey_ctx_ptr;
using utils::evp_pkey_ptr;

// The provider owns none of these types, so there is nothing to alias and the tests declare them
// against the same deleter helper. It supplies encoder callbacks rather than driving an encoder
// context, and it never builds certificates or TLS connections.
using encoder_ctx_ptr = std::unique_ptr<OSSL_ENCODER_CTX, utils::fn_deleter<OSSL_ENCODER_CTX_free>>;
using x509_ptr = std::unique_ptr<X509, utils::fn_deleter<X509_free>>;
using ssl_ctx_ptr = std::unique_ptr<SSL_CTX, utils::fn_deleter<SSL_CTX_free>>;
using ssl_ptr = std::unique_ptr<SSL, utils::fn_deleter<SSL_free>>;

} // namespace mpss_openssl::testing
