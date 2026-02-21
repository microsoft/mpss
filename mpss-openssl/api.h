// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/defines.h"
#include <openssl/core.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Deletes the key with the given name from safe storage.
     * @param[in] key_name The name of the key to delete.
     * @return True if the key was successfully deleted, false otherwise.
     */
    MPSS_OPENSSL_DECOR bool mpss_delete_key(const char *key_name);

    /**
     * @brief Initializes the MPSS OpenSSL provider.
     * @param[in] handle The OpenSSL core handle.
     * @param[in] in The dispatch table from OpenSSL.
     * @param[out] out The dispatch table to return to OpenSSL.
     * @param[out] provctx The provider context.
     * @return 1 on success, 0 on failure.
     */
    int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                           void **provctx);

    /**
     * @brief Checks whether an algorithm is available in the active backend.
     * @param[in] algorithm_name The algorithm name (e.g. "ecdsa_secp256r1_sha256").
     * @return True if the algorithm is available, false otherwise.
     */
    MPSS_OPENSSL_DECOR bool mpss_is_algorithm_available(const char *algorithm_name);

    /**
     * @brief Returns all algorithm names available in the active backend.
     * @return A null-terminated array of algorithm name strings. The returned pointer and strings are
     * valid for the lifetime of the process.
     */
    MPSS_OPENSSL_DECOR const char **mpss_get_available_algorithms(void);

    /**
     * @brief Retrieves the last error message.
     * @return A string describing the last error. The returned pointer is valid until the next call
     * to @ref mpss_get_error on the same thread.
     */
    MPSS_OPENSSL_DECOR const char *mpss_get_error(void);

    /**
     * @brief Returns the names of all available backends.
     * @return A null-terminated array of backend name strings (e.g., {"os", "yubikey", NULL}).
     * The returned pointer and strings are valid for the lifetime of the process.
     */
    MPSS_OPENSSL_DECOR const char **mpss_get_available_backends(void);

    /**
     * @brief Returns the name of the default backend.
     * @return The default backend name (e.g., "os" or "yubikey"), or an empty string if none is
     * available. The returned pointer is valid until the next call to @ref mpss_get_default_backend_name
     * on the same thread.
     */
    MPSS_OPENSSL_DECOR const char *mpss_get_default_backend_name(void);

#ifdef __cplusplus
}
#endif
