// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tests/test_entry.h"
#include "mpss/log.h"
#include "tests/scoped_env.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#ifdef __ANDROID__
#include <format>
#endif
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#ifdef __ANDROID__
#include <android/log.h>
#endif
#include <gtest/gtest.h>

#ifdef MPSS_BACKEND_YUBIKEY
#include "mpss/impl/yubikey/yk_piv.h"
#endif

namespace
{

#ifdef __ANDROID__
constexpr char mpss_logcat_tag[] = "MPSS";
constexpr char test_logcat_tag[] = "MPSS_TESTS";

void log_to_logcat(android_LogPriority priority, const char *tag, const std::string &message)
{
    __android_log_write(priority, tag, message.c_str());
}

std::shared_ptr<mpss::Logger> new_logcat_logger()
{
    using enum mpss::LogLevel;

    std::array<mpss::log_handler_t, mpss::log_level_count> log_handlers{};
    log_handlers[static_cast<std::size_t>(trace)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_VERBOSE, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(debug)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_DEBUG, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(info)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_INFO, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(warning)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_WARN, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(error)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_ERROR, mpss_logcat_tag, message);
    };

    std::array<mpss::flush_handler_t, mpss::log_level_count> flush_handlers{};
    std::array<mpss::close_handler_t, mpss::log_level_count> close_handlers{};
    return mpss::Logger::Create(std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers));
}

class LogcatEventListener : public ::testing::EmptyTestEventListener
{
  public:
    void OnTestStart(const ::testing::TestInfo &test_info) override
    {
        log_to_logcat(ANDROID_LOG_INFO, test_logcat_tag,
                      std::format("[ RUN      ] {}.{}", test_info.test_suite_name(), test_info.name()));
    }

    void OnTestPartResult(const ::testing::TestPartResult &result) override
    {
        if (!result.failed() && !result.skipped())
        {
            return;
        }

        const char *file_name = result.file_name();
        log_to_logcat(result.failed() ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, test_logcat_tag,
                      std::format("{}:{}: {}", nullptr == file_name ? "<unknown>" : file_name, result.line_number(),
                                  result.summary()));
    }

    void OnTestEnd(const ::testing::TestInfo &test_info) override
    {
        const ::testing::TestResult *result = test_info.result();
        const bool skipped = result->Skipped();
        const bool passed = result->Passed();
        const char *status = "FAILED";
        if (skipped)
        {
            status = "SKIPPED";
        }
        else if (passed)
        {
            status = "PASSED";
        }
        log_to_logcat(passed || skipped ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, test_logcat_tag,
                      std::format("[ {} ] {}.{} ({} ms)", status, test_info.test_suite_name(), test_info.name(),
                                  result->elapsed_time()));
    }

    void OnTestProgramEnd(const ::testing::UnitTest &unit_test) override
    {
        log_to_logcat(0 == unit_test.failed_test_count() ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, test_logcat_tag,
                      std::format("{} tests: {} passed, {} skipped, {} failed", unit_test.test_to_run_count(),
                                  unit_test.successful_test_count(), unit_test.skipped_test_count(),
                                  unit_test.failed_test_count()));
    }
};
#endif

#ifdef MPSS_BACKEND_YUBIKEY
std::string_view environment_variable(const char *name)
{
    const char *value = std::getenv(name); // NOLINT(concurrency-mt-unsafe) - single-threaded tests.
    return nullptr == value ? std::string_view{} : std::string_view{value};
}

std::optional<std::uint32_t> parse_serial(std::string_view text)
{
    std::uint32_t serial = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), serial);
    if (std::errc{} != error || text.data() + text.size() != end || 0 == serial)
    {
        return std::nullopt;
    }
    return serial;
}

// The serial numbers MPSS_TEST_YUBIKEYS lists, or nothing if the list is malformed.
std::optional<std::vector<std::uint32_t>> listed_test_yubikeys()
{
    const std::string_view list = environment_variable("MPSS_TEST_YUBIKEYS");
    std::vector<std::uint32_t> serials;
    if (list.empty())
    {
        return serials;
    }

    std::size_t start = 0;
    while (true)
    {
        const std::size_t comma = list.find(',', start);
        const std::optional<std::uint32_t> serial = parse_serial(list.substr(start, comma - start));
        if (!serial)
        {
            return std::nullopt;
        }
        serials.push_back(*serial);
        if (std::string_view::npos == comma)
        {
            return serials;
        }
        start = comma + 1;
    }
}
#endif

/**
 * @brief Global test environment that confines YubiKey tests to the devices MPSS_TEST_YUBIKEYS lists.
 *
 * For the duration of the run, MPSS_YUBIKEY_SERIAL selects the first listed device that is connected or, when
 * there is none, a serial no connected device has. Name-based calls in any test therefore cannot reach an
 * unlisted YubiKey. The variable's original state is restored after all tests complete.
 */
class YubiKeyEnvironment : public ::testing::Environment
{
  public:
    void SetUp() override
    {
#ifdef MPSS_BACKEND_YUBIKEY
        if (!listed_test_yubikeys())
        {
            GTEST_FAIL() << "MPSS_TEST_YUBIKEYS must list YubiKey serial numbers separated by commas.";
        }

        const std::vector<std::uint32_t> enabled = mpss::tests::test_yubikeys();
        if (!enabled.empty())
        {
            serial_env_.set(std::to_string(enabled.front()));
            mpss::GetLogger()->info("YubiKey tests use serial {} ({} listed and connected).", enabled.front(),
                                    enabled.size());
            return;
        }

        const auto connected =
            mpss::impl::yubikey::YubiKeyPIV::available_serials().value_or(std::vector<std::uint32_t>{});
        std::uint32_t absent = std::numeric_limits<std::uint32_t>::max();
        while (connected.end() != std::ranges::find(connected, absent))
        {
            --absent;
        }
        serial_env_.set(std::to_string(absent));
        mpss::GetLogger()->info("MPSS_TEST_YUBIKEYS lists no connected YubiKey, so YubiKey tests skip and name-based "
                                "calls default to absent serial {}.",
                                absent);
#endif
    }

  private:
    mpss::tests::ScopedEnvironmentVariable serial_env_{"MPSS_YUBIKEY_SERIAL"};
};

} // namespace

std::vector<std::uint32_t> mpss::tests::test_yubikeys()
{
    std::vector<std::uint32_t> enabled;
#ifdef MPSS_BACKEND_YUBIKEY
    const auto connected = mpss::impl::yubikey::YubiKeyPIV::available_serials().value_or(std::vector<std::uint32_t>{});
    for (const std::uint32_t serial : listed_test_yubikeys().value_or(std::vector<std::uint32_t>{}))
    {
        if (connected.end() != std::ranges::find(connected, serial) &&
            enabled.end() == std::ranges::find(enabled, serial))
        {
            enabled.push_back(serial);
        }
    }
#endif
    return enabled;
}

std::optional<std::uint32_t> mpss::tests::test_yubikey_serial()
{
#ifdef MPSS_BACKEND_YUBIKEY
    const std::optional<std::uint32_t> selected = parse_serial(environment_variable("MPSS_YUBIKEY_SERIAL"));
    const std::vector<std::uint32_t> enabled = test_yubikeys();
    if (selected && enabled.end() != std::ranges::find(enabled, *selected))
    {
        return selected;
    }
#endif
    return std::nullopt;
}

int mpss::tests::run_all_tests(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
#ifdef __ANDROID__
    mpss::GetOrSetLogger(new_logcat_logger());
#endif
    mpss::GetLogger()->set_level(mpss::LogLevel::trace);
    ::testing::AddGlobalTestEnvironment(new YubiKeyEnvironment); // NOLINT(*-owning-memory)
#ifdef __ANDROID__
    ::testing::UnitTest::GetInstance()->listeners().Append(new LogcatEventListener); // NOLINT(*-owning-memory)
#endif
    const int result = RUN_ALL_TESTS();
    return 0 == ::testing::UnitTest::GetInstance()->test_to_run_count() ? 1 : result;
}
