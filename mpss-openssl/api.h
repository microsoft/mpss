// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/defines.h"
#include <openssl/core.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <stddef.h>

/** @brief Key policy constants for use with the "mpss_key_policy" provider parameter. */
// NOLINTBEGIN(*-macro-to-enum) - C/C++ dual header; macros required for C compatibility.
#define MPSS_KEY_POLICY_NONE 0U

#ifdef MPSS_BACKEND_YUBIKEY
#define MPSS_KEY_POLICY_YUBIKEY_PIN_NEVER 1U
#define MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE 2U
#define MPSS_KEY_POLICY_YUBIKEY_PIN_ALWAYS 3U
#define MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER (1U << 4U)
#define MPSS_KEY_POLICY_YUBIKEY_TOUCH_ALWAYS (2U << 4U)
#define MPSS_KEY_POLICY_YUBIKEY_TOUCH_CACHED (3U << 4U)
#endif

#define MPSS_KEY_POLICY_APPLE_SECURE_ENCLAVE_USER_PRESENCE (1ULL << 8U)
// NOLINTEND(*-macro-to-enum)

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Deletes every key stored under the given name from safe storage.
     *
     * Does not require the name to resolve to a single usable key, so it also clears a name that
     * opening refuses as ambiguous. A name that holds nothing is already in the requested state.
     *
     * @param[in] key_name The name to clear.
     * @return True if the name holds no key afterwards, false if a key could not be removed or the
     * storage could not be read.
     */
    MPSS_OPENSSL_DECOR bool mpss_delete_key(const char *key_name);

    /**
     * @brief Deletes every key stored under the given name from the specified backend.
     *
     * Does not require the name to resolve to a single usable key, so it also clears a name that
     * opening refuses as ambiguous. A name that holds nothing is already in the requested state.
     *
     * @param[in] key_name The name to clear.
     * @param[in] backend_name The backend to clear the name in.
     * @return True if the name holds no key afterwards, false if a key could not be removed or the
     * storage could not be read.
     */
    MPSS_OPENSSL_DECOR bool mpss_delete_key_from_backend(const char *key_name, const char *backend_name);

    /**
     * @brief Initializes the MPSS OpenSSL provider.
     * @param[in] handle The OpenSSL core handle.
     * @param[in] in The dispatch table from OpenSSL.
     * @param[out] out The dispatch table to return to OpenSSL.
     * @param[out] provctx The provider context.
     * @return 1 on success, 0 on failure.
     */
    // NOLINTNEXTLINE(readability-redundant-declaration) - intentional: documents the provider entry point.
    int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                           void **provctx);

    /**
     * @brief Checks whether an algorithm is available in the default backend.
     *
     * What "available" means is decided by the backend and is not uniform across backends. A backend
     * may answer by probing at runtime -- creating a scratch key, signing, verifying and deleting it --
     * in which case a true result means the algorithm works end-to-end at that moment. A backend may
     * instead answer from static capability, in which case a true result means only that the backend
     * implements the algorithm and says nothing about whether its device is attached or usable. The
     * YubiKey backend answers statically and so reports availability with no device present; the
     * operating-system backends probe. Treat a true result as "worth attempting", not as a guarantee
     * that the next call will succeed.
     *
     * @param[in] algorithm_name The algorithm name (e.g. "ecdsa_secp256r1_sha256").
     * @return true if the algorithm is available, false if it is unavailable or if availability could
     * not be determined. The two are distinguished by @ref mpss_has_error.
     */
    MPSS_OPENSSL_DECOR bool mpss_is_algorithm_available(const char *algorithm_name);

    /**
     * @brief Checks whether an algorithm is available in the specified backend.
     *
     * The meaning of "available" is the named backend's; see @ref mpss_is_algorithm_available.
     *
     * @param[in] algorithm_name The algorithm name (e.g. "ecdsa_secp256r1_sha256").
     * @param[in] backend_name The backend to check (e.g. "os", "yubikey").
     * @return true if the algorithm is available, false if it is unavailable or if availability could
     * not be determined. The two are distinguished by @ref mpss_has_error.
     */
    MPSS_OPENSSL_DECOR bool mpss_is_algorithm_available_in_backend(const char *algorithm_name,
                                                                   const char *backend_name);

    /**
     * @brief Returns all algorithm names available in the default backend.
     *
     * Each algorithm is decided as described in @ref mpss_is_algorithm_available and inherits its
     * meaning of "available". The list is recomputed on every call.
     *
     * @return A null-terminated array of algorithm name strings. The array is valid until the next
     * call to @ref mpss_get_available_algorithms on the same thread, and is destroyed when that
     * thread exits; copy it if it must outlive either. The strings it points to are valid for the
     * lifetime of the process.
     */
    MPSS_OPENSSL_DECOR const char **mpss_get_available_algorithms(void);

    /**
     * @brief Retrieves the last error message recorded on this thread.
     *
     * The last error is per-thread: a call that fails on one thread leaves nothing for another
     * thread to read, so it must be retrieved on the thread that made the failing call. This does
     * not consume the error; see @ref mpss_clear_error.
     *
     * @return A string describing the last error, or an empty string if there is none. The returned
     * pointer is valid until the next call to @ref mpss_get_error on the same thread, and the string
     * it points to is destroyed when that thread exits; copy it if it must outlive either.
     */
    MPSS_OPENSSL_DECOR const char *mpss_get_error(void);

    /**
     * @brief Determines whether the last operation on this thread left an error.
     *
     * Equivalent to testing whether @ref mpss_get_error returns a non-empty string, but copies
     * nothing and does not invalidate the pointer previously returned by @ref mpss_get_error.
     * Like @ref mpss_get_error, this does not clear the last error.
     *
     * @return true if an error is set, false otherwise.
     */
    MPSS_OPENSSL_DECOR bool mpss_has_error(void);

    /**
     * @brief Clears the last error for this thread.
     *
     * Every fallible MPSS operation already clears the last error on entry, so this is not needed
     * to keep one call's error from leaking into the next.
     *
     * It is for marking an error as handled. Since @ref mpss_get_error does not consume the error,
     * an outer layer that inspects it cannot tell an error an inner layer already reported from a
     * fresh one. Clearing it once handled keeps it from being reported twice. Entering another MPSS
     * call does not substitute for this, as the error must survive until whoever handles it has run.
     *
     * This does not invalidate the pointer previously returned by @ref mpss_get_error, which stays
     * valid until that function is called again on the same thread.
     */
    MPSS_OPENSSL_DECOR void mpss_clear_error(void);

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
