// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/defines.h"

#ifdef MPSS_BACKEND_YUBIKEY

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief Maximum buffer size (in bytes) passed to @ref mpss_request_pin_handler_t, including the null terminator. */
#define MPSS_PIN_BUF_SIZE ((size_t)256)

    /** @brief PIN status values passed to @ref mpss_request_pin_handler_t. */
    enum mpss_pin_status
    {
        MPSS_PIN_STATUS_FIRST_ATTEMPT = 0, /**< First PIN request for this operation. */
        MPSS_PIN_STATUS_WRONG_PIN = 1,     /**< Previous PIN was incorrect. */
    };

    /** @brief PIN result values passed to @ref mpss_notify_pin_result_handler_t. */
    enum mpss_pin_result
    {
        MPSS_PIN_RESULT_OK = 0,        /**< PIN verified successfully. */
        MPSS_PIN_RESULT_WRONG_PIN = 1, /**< PIN was incorrect. */
        MPSS_PIN_RESULT_LOCKED = 2,    /**< PIN is locked. */
        MPSS_PIN_RESULT_ERROR = 3,     /**< Non-PIN error. */
        /** The PIN never reached the device, so no retry was spent. Follows a canceled, failing, or
            withheld PIN request, so every request is answered by exactly one result. */
        MPSS_PIN_RESULT_NOT_ATTEMPTED = 4,
    };

    /**
     * @brief Target metadata, valid only for the duration of a callback.
     *
     * Strings are non-null and null-terminated. Copy them before returning if needed later.
     * For YubiKey, device_id is its decimal serial. reader_name identifies the current transport,
     * not trusted hardware identity. key_name is empty for device-only operations.
     */
    typedef struct mpss_interaction_context
    {
        const char *backend_name;
        const char *device_id;
        const char *key_name;
        const char *reader_name;
    } mpss_interaction_context_t;

    /**
     * @brief Requests a PIN for the specified target.
     * @param target Device, key, and reader information, valid only during the callback.
     * @param operation Human-readable reason (e.g., "sign with key 'my-key'").
     * @param last_status Status of the previous PIN attempt (@ref mpss_pin_status).
     * @param retries_remaining PIN retries remaining, or -1 if unknown.
     * @param pin_buf Buffer for the null-terminated PIN; never log or persist its contents.
     * @param pin_buf_size Buffer size in bytes (always @ref MPSS_PIN_BUF_SIZE).
     * @param user_data Application pointer supplied when installing the handler.
     * @return true if the PIN was provided, false to cancel.
     */
    typedef bool (*mpss_request_pin_handler_t)(const mpss_interaction_context_t *target, const char *operation,
                                               int last_status, int retries_remaining, char *pin_buf,
                                               size_t pin_buf_size, void *user_data);
    /** @brief Reports a PIN result (@ref mpss_pin_result) and remaining retries (-1 if unknown). */
    typedef void (*mpss_notify_pin_result_handler_t)(const mpss_interaction_context_t *target, int result,
                                                     int retries_remaining, void *user_data);
    /** @brief Reports the start of an operation that may require touch. */
    typedef void (*mpss_notify_touch_handler_t)(const mpss_interaction_context_t *target, void *user_data);
    /** @brief Reports completion; success is false if the operation failed or touch timed out. */
    typedef void (*mpss_notify_touch_complete_handler_t)(const mpss_interaction_context_t *target, bool success,
                                                         void *user_data);

    /**
     * @brief Installs a custom interaction handler for YubiKey operations.
     *
     * When installed, the MPSS_YUBIKEY_PIN environment variable is ignored; the
     * request_pin callback has full control over PIN retrieval.
     *
     * Any callback may be NULL, in which case the corresponding operation is a no-op
     * (a NULL request_pin always cancels, i.e., returns no PIN).
     * Callbacks from different devices may run concurrently.
     *
     * @param[in] request_pin Called when a PIN is needed.
     * @param[in] notify_pin_result Called after each PIN attempt with the result. May be NULL.
     * @param[in] notify_touch_needed Called when a touch-requiring operation starts.
     * @param[in] notify_touch_complete Called when the touch-requiring operation finishes, with whether it succeeded.
     * @param[in] user_data Forwarded unchanged to callbacks. MPSS does not own it; keep it valid for callbacks
     * already in flight even after replacing the handler.
     */
    MPSS_OPENSSL_DECOR void mpss_set_interaction_handler(mpss_request_pin_handler_t request_pin,
                                                         mpss_notify_pin_result_handler_t notify_pin_result,
                                                         mpss_notify_touch_handler_t notify_touch_needed,
                                                         mpss_notify_touch_complete_handler_t notify_touch_complete,
                                                         void *user_data);

    /**
     * @brief Resets the interaction handler to the default terminal-based handler.
     *
     * The default handler reads the PIN from the MPSS_YUBIKEY_PIN environment variable,
     * or prompts interactively on the terminal if the variable is not set.
     */
    MPSS_OPENSSL_DECOR void mpss_reset_default_interaction_handler(void);

#ifdef __cplusplus
}
#endif

#endif // MPSS_BACKEND_YUBIKEY
