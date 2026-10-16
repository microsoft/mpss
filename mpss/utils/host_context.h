// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <openssl/crypto.h>
#include <openssl/provider.h>

namespace mpss::utils
{

/**
 * @brief The OpenSSL library context MPSS does its own OpenSSL work in.
 *
 * It holds only OpenSSL's built-in default provider. OpenSSL's default library context belongs to the
 * application, whose providers and default properties need not offer what MPSS needs, so work done here neither
 * depends on nor runs the application's OpenSSL configuration. Fetches made here still name `provider=default`.
 *
 * Immortal like BackendRegistry::Instance(): never freed, so it outlives host statics that call MPSS during exit.
 * OSSL_LIB_CTX use is thread-safe.
 *
 * @return The context, or nullptr if it could not be created.
 */
[[nodiscard]]
inline OSSL_LIB_CTX *host_context()
{
    static OSSL_LIB_CTX *const context = [] {
        OSSL_LIB_CTX *created = OSSL_LIB_CTX_new();
        if (nullptr != created && nullptr == OSSL_PROVIDER_load(created, "default"))
        {
            OSSL_LIB_CTX_free(created);
            created = nullptr;
        }

        return created;
    }();
    return context;
}

} // namespace mpss::utils
