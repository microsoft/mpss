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
    };

    /**
     * @brief Callback type for requesting a YubiKey PIN from the user.
     * @param context A human-readable reason for the PIN request (e.g., "sign with key 'my-key'").
     * @param last_status Status of the previous PIN attempt (@ref mpss_pin_status).
     * @param retries_remaining PIN retries remaining on the device, or -1 if unknown.
     * @param pin_buf Buffer to write the null-terminated PIN into.
     * @param pin_buf_size Size of pin_buf in bytes (always @ref MPSS_PIN_BUF_SIZE).
     * @return true if the PIN was provided, false if the user cancelled.
     * @warning Implementations must never log or persist the PIN.
     */
    typedef bool (*mpss_request_pin_handler_t)(const char *context, int last_status, int retries_remaining,
                                               char *pin_buf, size_t pin_buf_size);

    /**
     * @brief Callback type for PIN result notifications.
     * @param result The outcome of the PIN attempt (@ref mpss_pin_result).
     * @param retries_remaining PIN retries remaining on the device, or -1 if unknown.
     */
    typedef void (*mpss_notify_pin_result_handler_t)(int result, int retries_remaining);

    /**
     * @brief Callback type for touch notifications.
     */
    typedef void (*mpss_notify_touch_handler_t)(void);

    /**
     * @brief Installs a custom interaction handler for YubiKey operations.
     *
     * When installed, the MPSS_YUBIKEY_PIN environment variable is ignored; the
     * request_pin callback has full control over PIN retrieval.
     *
     * Any callback may be NULL, in which case the corresponding operation is a no-op
     * (a NULL request_pin always cancels, i.e., returns no PIN).
     *
     * @param[in] request_pin Called when a PIN is needed.
     * @param[in] notify_pin_result Called after each PIN attempt with the result. May be NULL.
     * @param[in] notify_touch_needed Called when a touch-requiring operation starts.
     * @param[in] notify_touch_complete Called when the touch-requiring operation completes.
     */
    MPSS_OPENSSL_DECOR void mpss_set_interaction_handler(mpss_request_pin_handler_t request_pin,
                                                         mpss_notify_pin_result_handler_t notify_pin_result,
                                                         mpss_notify_touch_handler_t notify_touch_needed,
                                                         mpss_notify_touch_handler_t notify_touch_complete);

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
