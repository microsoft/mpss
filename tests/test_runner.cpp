// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/log.h"
#include "tests/compat_env.h"
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>

#ifdef MPSS_BACKEND_YUBIKEY
#include "mpss/impl/yubikey/yk_piv.h"
#endif

namespace
{

/**
 * @brief Global test environment that auto-selects a YubiKey when multiple are present.
 *
 * When multiple YubiKeys are connected and MPSS_YUBIKEY_SERIAL is not set, this picks
 * the first available device so that the multi-device guard does not block key creation.
 * The original env var state is restored after all tests complete.
 */
class YubiKeyEnvironment : public ::testing::Environment
{
  public:
    void SetUp() override
    {
#ifdef MPSS_BACKEND_YUBIKEY
        const char *existing = std::getenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        if (nullptr != existing)
        {
            saved_serial_env_ = existing;
            return;
        }

        const auto serials = mpss::impl::yubikey::YubiKeyPIV::available_serials();
        if (serials.size() > 1)
        {
            auto_selected_ = true;
            const std::string serial_str = std::to_string(serials.front());
            setenv("MPSS_YUBIKEY_SERIAL", serial_str.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
            mpss::GetLogger()->info("Multiple YubiKeys detected; auto-selected serial {} for tests.", serials.front());
        }
#endif
    }

    void TearDown() override
    {
#ifdef MPSS_BACKEND_YUBIKEY
        if (auto_selected_)
        {
            unsetenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        }
        else if (!saved_serial_env_.empty())
        {
            setenv("MPSS_YUBIKEY_SERIAL", saved_serial_env_.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
#endif
    }

  private:
    std::string saved_serial_env_;
    bool auto_selected_{false};
};

} // namespace

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    mpss::GetLogger()->set_level(mpss::LogLevel::trace);
    ::testing::AddGlobalTestEnvironment(new YubiKeyEnvironment); // NOLINT(*-owning-memory)
    return RUN_ALL_TESTS();
}
