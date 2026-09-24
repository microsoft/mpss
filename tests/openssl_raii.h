// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/utils/ossl_ptr.h"
#include <memory>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace mpss_openssl::tests
{

using mpss::utils::bio_ptr;
using mpss::utils::evp_pkey_ctx_ptr;
using mpss::utils::evp_pkey_ptr;

// Test-only OpenSSL objects use the same shared deleter.
using encoder_ctx_ptr = std::unique_ptr<OSSL_ENCODER_CTX, mpss::utils::fn_deleter<OSSL_ENCODER_CTX_free>>;
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, mpss::utils::fn_deleter<EVP_MD_CTX_free>>;
using x509_ptr = std::unique_ptr<X509, mpss::utils::fn_deleter<X509_free>>;
using ssl_ctx_ptr = std::unique_ptr<SSL_CTX, mpss::utils::fn_deleter<SSL_CTX_free>>;
using ssl_ptr = std::unique_ptr<SSL, mpss::utils::fn_deleter<SSL_free>>;

} // namespace mpss_openssl::tests
