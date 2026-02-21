// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/interaction_handler.h"

#ifdef MPSS_BACKEND_YUBIKEY

#include <array>
#include <cstring>
#include <mpss/interaction_handler.h>
#include <mpss/utils/scope_guard.h>
#include <openssl/crypto.h>
#include <string>

namespace
{

/**
 * @brief Adapter that wraps C function-pointer callbacks into the C++ InteractionHandler interface.
 */
class CInteractionHandler : public mpss::InteractionHandler
{
  public:
    CInteractionHandler(mpss_request_pin_handler_t request_pin, mpss_notify_touch_handler_t notify_touch_needed,
                        mpss_notify_touch_handler_t notify_touch_complete)
        : request_pin_{request_pin}, notify_touch_needed_{notify_touch_needed},
          notify_touch_complete_{notify_touch_complete}
    {
    }

    [[nodiscard]] std::optional<mpss::SecureString> request_pin(std::string_view context) override
    {
        if (nullptr == request_pin_)
        {
            return std::nullopt;
        }

        // Use a stack buffer for the PIN; securely wipe it when leaving scope.
        std::array<char, MPSS_PIN_BUF_SIZE> pin_buf{};
        SCOPE_GUARD(::OPENSSL_cleanse(pin_buf.data(), pin_buf.size()));

        const std::string ctx_str{context};

        if (!request_pin_(ctx_str.c_str(), pin_buf.data(), pin_buf.size()))
        {
            return std::nullopt;
        }

        // Ensure null-termination before constructing the SecureString.
        pin_buf[pin_buf.size() - 1] = '\0';
        return mpss::SecureString{pin_buf.data()};
    }

    void notify_touch_needed() override
    {
        if (nullptr != notify_touch_needed_)
        {
            notify_touch_needed_();
        }
    }

    void notify_touch_complete() override
    {
        if (nullptr != notify_touch_complete_)
        {
            notify_touch_complete_();
        }
    }

  private:
    mpss_request_pin_handler_t request_pin_;
    mpss_notify_touch_handler_t notify_touch_needed_;
    mpss_notify_touch_handler_t notify_touch_complete_;
};

} // namespace

void mpss_set_interaction_handler(mpss_request_pin_handler_t request_pin,
                                  mpss_notify_touch_handler_t notify_touch_needed,
                                  mpss_notify_touch_handler_t notify_touch_complete)
{
    auto handler = std::make_shared<CInteractionHandler>(request_pin, notify_touch_needed, notify_touch_complete);
    mpss::GetOrSetInteractionHandler(std::move(handler));
}

void mpss_reset_default_interaction_handler(void)
{
    mpss::ResetDefaultInteractionHandler();
}

#endif // MPSS_BACKEND_YUBIKEY
