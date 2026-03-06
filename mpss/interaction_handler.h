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
 * @brief Abstract interface for user interaction during YubiKey operations.
 *
 * Applications can implement this interface to provide custom PIN entry (e.g., GUI dialog) and touch notification
 * behavior. A custom interaction handler is installed with @ref GetOrSetInteractionHandler.
 *
 * @note Getting and setting the handler are both thread-safe.
 */
class InteractionHandler
{
  public:
    virtual ~InteractionHandler() = default;

    /**
     * @brief Request the YubiKey PIN from the user.
     * @param context Human-readable reason (e.g., "sign data", "generate key").
     * @return The PIN, or std::nullopt if the user cancelled.
     * @warning Implementations must never log or store the returned PIN beyond the immediate operation.
     */
    [[nodiscard]] virtual std::optional<SecureString> request_pin(std::string_view context) = 0;

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
