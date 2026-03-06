// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/log.h"

#include <cstddef>
#include <shared_mutex>
#include <string>

namespace mpss
{

std::shared_ptr<Logger> GetOrSetLogger(std::shared_ptr<Logger> new_logger)
{
    static std::shared_mutex mtx;
    static std::shared_ptr<Logger> logger = NewDefaultLogger();
    if (nullptr != new_logger)
    {
        std::unique_lock lock{mtx};
        logger = std::move(new_logger);
        return logger;
    }
    std::shared_lock lock{mtx};
    return logger;
}

void Logger::log(LogLevel level, const std::string &msg) const
{
    const std::size_t level_index = static_cast<std::size_t>(level);
    const std::size_t min_level_index = static_cast<std::size_t>(log_level_);
    if (level_index >= log_level_count || level_index < min_level_index)
    {
        // Invalid log level; ignore.
        return;
    }

    std::scoped_lock lock{mtx_};
    if (log_handlers_[level_index])
    {
        log_handlers_[level_index](msg);
    }
}

void Logger::flush_internal() const
{
    for (std::size_t i = 0; i < log_level_count; i++)
    {
        if (flush_handlers_[i])
        {
            flush_handlers_[i]();
        }
    }
}

void Logger::close_internal()
{
    flush_internal();
    for (std::size_t i = 0; i < log_level_count; i++)
    {
        if (close_handlers_[i])
        {
            close_handlers_[i]();
        }
    }

    // Set all handlers to null after closing.
    log_handlers_.fill(nullptr);
    flush_handlers_.fill(nullptr);
    close_handlers_.fill(nullptr);
}

} // namespace mpss

namespace
{

using enum mpss::LogLevel;

mpss::LogLevel to_cpp_level(mpss_log_level_t level)
{
    switch (level)
    {
    case MPSS_LOG_LEVEL_TRACE:
        return trace;
    case MPSS_LOG_LEVEL_DEBUG:
        return debug;
    case MPSS_LOG_LEVEL_INFO:
        return info;
    case MPSS_LOG_LEVEL_WARNING:
        return warning;
    case MPSS_LOG_LEVEL_ERROR:
        return error;
    case MPSS_LOG_LEVEL_SUPPRESS:
    default:
        return suppress;
    }
}

mpss_log_level_t to_c_level(mpss::LogLevel level)
{
    switch (level)
    {
    case trace:
        return MPSS_LOG_LEVEL_TRACE;
    case debug:
        return MPSS_LOG_LEVEL_DEBUG;
    case info:
        return MPSS_LOG_LEVEL_INFO;
    case warning:
        return MPSS_LOG_LEVEL_WARNING;
    case error:
        return MPSS_LOG_LEVEL_ERROR;
    case suppress:
    default:
        return MPSS_LOG_LEVEL_SUPPRESS;
    }
}

} // namespace

mpss_log_level_t mpss_log_get_level(void)
{
    auto logger = mpss::GetLogger();
    if (nullptr == logger)
    {
        return MPSS_LOG_LEVEL_SUPPRESS;
    }
    return to_c_level(logger->get_level());
}

void mpss_log_set_level(mpss_log_level_t level)
{
    auto logger = mpss::GetLogger();
    if (nullptr != logger)
    {
        logger->set_level(to_cpp_level(level));
    }
}

void mpss_log(mpss_log_level_t level, const char *message)
{
    if (nullptr == message)
    {
        return;
    }
    auto logger = mpss::GetLogger();
    if (nullptr != logger)
    {
        logger->log(to_cpp_level(level), std::string{message});
    }
}

void mpss_log_trace(const char *message)
{
    mpss_log(MPSS_LOG_LEVEL_TRACE, message);
}

void mpss_log_debug(const char *message)
{
    mpss_log(MPSS_LOG_LEVEL_DEBUG, message);
}

void mpss_log_info(const char *message)
{
    mpss_log(MPSS_LOG_LEVEL_INFO, message);
}

void mpss_log_warning(const char *message)
{
    mpss_log(MPSS_LOG_LEVEL_WARNING, message);
}

void mpss_log_error(const char *message)
{
    mpss_log(MPSS_LOG_LEVEL_ERROR, message);
}

void mpss_log_flush(void)
{
    auto logger = mpss::GetLogger();
    if (nullptr != logger)
    {
        logger->flush();
    }
}

void mpss_log_close(void)
{
    auto logger = mpss::GetLogger();
    if (nullptr != logger)
    {
        logger->close();
    }
}

void mpss_log_set_custom_logger(mpss_log_handler_t log_handlers[MPSS_LOG_LEVEL_COUNT],
                                mpss_flush_handler_t flush_handlers[MPSS_LOG_LEVEL_COUNT],
                                mpss_close_handler_t close_handlers[MPSS_LOG_LEVEL_COUNT])
{
    std::array<mpss::log_handler_t, mpss::log_level_count> cpp_log{};
    std::array<mpss::flush_handler_t, mpss::log_level_count> cpp_flush{};
    std::array<mpss::close_handler_t, mpss::log_level_count> cpp_close{};

    for (std::size_t i = 0; i < mpss::log_level_count; i++)
    {
        if (log_handlers && log_handlers[i])
        {
            mpss_log_handler_t cb = log_handlers[i];
            cpp_log[i] = [cb](std::string msg) { cb(msg.c_str()); };
        }
        if (flush_handlers && flush_handlers[i])
        {
            mpss_flush_handler_t cb = flush_handlers[i];
            cpp_flush[i] = [cb]() { cb(); };
        }
        if (close_handlers && close_handlers[i])
        {
            mpss_close_handler_t cb = close_handlers[i];
            cpp_close[i] = [cb]() { cb(); };
        }
    }

    auto logger = mpss::Logger::Create(std::move(cpp_log), std::move(cpp_flush), std::move(cpp_close));
    mpss::GetOrSetLogger(std::move(logger));
}

void mpss_log_reset_default(void)
{
    mpss::GetOrSetLogger(mpss::NewDefaultLogger());
}
