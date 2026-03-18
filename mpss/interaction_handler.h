// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/config.h"

#ifdef MPSS_BACKEND_YUBIKEY

#include "mpss/secure_types.h"
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
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
 * @brief Context passed to @ref InteractionHandler::request_pin.
 */
struct PinRequestContext
{
    std::string_view operation; /**< Human-readable reason (e.g., "sign with key 'my-key'"). */
    PinStatus last_status;      /**< Status of the previous PIN attempt. */
    int retries_remaining;      /**< PIN retries remaining on the device, or -1 if unknown. */
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
     * This is a notification callback - the return value is void. Implementations can use it to
     * update UI (e.g., dismiss a dialog on success, show a "PIN locked" warning). The default
     * implementation does nothing.
     *
     * @param result The outcome of the PIN attempt.
     * @param retries_remaining PIN retries remaining on the device, or -1 if unknown.
     */
    virtual void notify_pin_result(PinResult result, int retries_remaining)
    {
        (void)result;
        (void)retries_remaining;
    }

    /** @brief Notify that a touch-requiring operation is starting. */
    virtual void notify_touch_needed() = 0;

    /** @brief Notify that the touch-requiring operation has completed. */
    virtual void notify_touch_complete() = 0;
};

/**
 * @brief Creates a new default terminal-based interaction handler.
 * @return A shared pointer to the new handler.
 */
std::shared_ptr<InteractionHandler> NewDefaultInteractionHandler();

/**
 * @brief Gets or replaces the global interaction handler.
 * @param[in] new_handler If non-null, replaces the current global handler. If null, the current global handler is
 * returned without replacing it.
 * @return The current global interaction handler (after any replacement).
 * @note This function is thread-safe for both reading and writing.
 */
inline std::shared_ptr<InteractionHandler> GetOrSetInteractionHandler(
    std::shared_ptr<InteractionHandler> new_handler = nullptr)
{
    static std::shared_mutex mtx;
    static std::shared_ptr<InteractionHandler> handler = NewDefaultInteractionHandler();
    if (nullptr != new_handler)
    {
        std::unique_lock lock{mtx};
        handler = std::move(new_handler);
        return handler;
    }
    std::shared_lock lock{mtx};
    return handler;
}

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
