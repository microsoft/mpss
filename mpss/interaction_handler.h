// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/config.h"

#ifdef MPSS_BACKEND_YUBIKEY

#include "mpss/defines.h"
#include "mpss/secure_types.h"
#include <memory>
#include <optional>
#include <string_view>

namespace mpss
{

/**
 * @brief Result of a PIN authentication attempt.
 */
enum class PinResult
{
    ok,        /**< PIN verified successfully. */
    wrong_pin, /**< PIN was incorrect (retries may remain). */
    locked,    /**< PIN is locked (too many wrong attempts). Use PUK to unlock. */
    error,     /**< Non-PIN error (e.g., device disconnected). */
    /**
     * @brief The PIN was never presented to the device, so no retry was spent.
     *
     * Reported when the handler cancels or throws, and when MPSS withholds a value the device has
     * already refused. It closes the loop for a handler that opened UI in @ref
     * InteractionHandler::request_pin: every PIN request is answered by exactly one result.
     */
    not_attempted,
};

/**
 * @brief Status of the previous PIN attempt, passed to @ref InteractionHandler::request_pin.
 */
enum class PinStatus
{
    first_attempt, /**< First PIN request for this operation. */
    wrong_pin,     /**< Previous PIN was incorrect. */
};

/**
 * @brief Identifies the target of an interaction, not proof of hardware identity.
 *
 * Views remain valid for the callback only; copy values needed by asynchronous UI.
 */
struct InteractionContext
{
    std::string_view backend_name; /**< Backend handling the operation. */
    std::string_view device_id;    /**< Canonical decimal serial for YubiKey. */
    std::string_view key_name;     /**< Requested key name, or empty for device-only operations. */
    std::string_view reader_name;  /**< Reader used by this connection; informational, not a stable identifier. */
};

/**
 * @brief Context passed to @ref InteractionHandler::request_pin.
 */
struct PinRequestContext
{
    std::string_view operation;  /**< Human-readable reason (e.g., "sign with key 'my-key'"). */
    PinStatus last_status;       /**< Status of the previous PIN attempt. */
    int retries_remaining;       /**< PIN retries remaining on the device, or -1 if unknown. */
    InteractionContext target{}; /**< Device, key, and reader for this request. */
};

/**
 * @brief Abstract interface for user interaction during YubiKey operations.
 *
 * Applications can implement this interface to provide custom PIN entry (e.g., GUI dialog) and touch notification
 * behavior. A custom interaction handler is installed with @ref GetOrSetInteractionHandler.
 *
 * The handler controls the retry policy: MPSS calls @ref request_pin in a loop until it returns std::nullopt
 * (cancel), or until the PIN is accepted or locked. Returning std::nullopt at any point stops the loop.
 *
 * @note Getting and setting the handler are both thread-safe.
 * @note Requests from different devices may run concurrently. Use the target context to select
 * credentials and associate notifications with the correct UI.
 */
class InteractionHandler
{
  public:
    virtual ~InteractionHandler() = default;

    /**
     * @brief Request the YubiKey PIN from the user.
     *
     * Called in a loop by MPSS until the PIN is accepted, the handler cancels (returns std::nullopt),
     * or the PIN becomes locked. The handler controls the retry policy by deciding when to return
     * std::nullopt.
     *
     * @param context Information about the request, including the operation description, previous
     *                attempt status, and remaining retries on the device.
     * @return The PIN, or std::nullopt to cancel.
     * @warning Implementations must never log or store the returned PIN beyond the immediate operation.
     */
    [[nodiscard]]
    virtual std::optional<SecureString> request_pin(const PinRequestContext &context) = 0;

    /**
     * @brief Called after each PIN authentication attempt with the result.
     *
     * This is a notification callback; the return value is void. Implementations can use it to
     * update UI (e.g., dismiss a dialog on success, show a "PIN locked" warning). The default
     * implementation does nothing.
     *
     * Exactly one result follows every @ref request_pin call, including @ref PinResult::not_attempted
     * when the PIN never reaches the device, so UI opened while answering a request can always be
     * taken down again. Exceptions thrown from here are swallowed on the paths that report
     * not_attempted, since those are already reporting a failure.
     *
     * @param target Device, key, and reader associated with the request.
     * @param result The outcome of the PIN attempt.
     * @param retries_remaining PIN retries remaining on the device, or -1 if unknown.
     */
    virtual void notify_pin_result([[maybe_unused]] const InteractionContext &target, [[maybe_unused]] PinResult result,
                                   [[maybe_unused]] int retries_remaining)
    {
    }

    /** @brief Notify that a touch-requiring operation is starting. */
    virtual void notify_touch_needed(const InteractionContext &target) = 0;

    /**
     * @brief Notify that the touch-requiring operation has finished.
     * @param target Device, key, and reader associated with the operation.
     * @param success True if the operation completed, false if it failed (for example, the touch timed out).
     */
    virtual void notify_touch_complete(const InteractionContext &target, bool success) = 0;
};

/**
 * @brief Creates a new default terminal-based interaction handler.
 * @return A shared pointer to the new handler.
 */
MPSS_DECOR std::shared_ptr<InteractionHandler> NewDefaultInteractionHandler();

/**
 * @brief Gets or replaces the global interaction handler.
 * @param[in] new_handler If non-null, replaces the current global handler. If null, the current global handler is
 * returned without replacing it.
 * @return The current global interaction handler (after any replacement).
 * @note This function is thread-safe for both reading and writing.
 */
MPSS_DECOR std::shared_ptr<InteractionHandler> GetOrSetInteractionHandler(
    std::shared_ptr<InteractionHandler> new_handler = nullptr);

/**
 * @brief Gets the current global interaction handler.
 * @return A shared pointer to the global interaction handler.
 */
inline std::shared_ptr<InteractionHandler> GetInteractionHandler()
{
    return GetOrSetInteractionHandler(nullptr);
}

/**
 * @brief Resets the global interaction handler back to the default terminal handler.
 */
inline void ResetDefaultInteractionHandler()
{
    GetOrSetInteractionHandler(NewDefaultInteractionHandler());
}

} // namespace mpss

#endif // MPSS_BACKEND_YUBIKEY
