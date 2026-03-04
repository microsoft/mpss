// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/log_c.h"
#include <array>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace mpss
{

/**
 * @brief Log level constants for the logger.
 */
enum class LogLevel : std::size_t
{
    trace,
    debug,
    info,
    warning,
    error,
    suppress,
};

/**
 * @brief The number of actionable log levels (excludes suppress).
 */
constexpr std::size_t log_level_count = static_cast<std::size_t>(LogLevel::suppress);

/**
 * @brief Callback type for log handlers.
 * @param msg The log message string.
 */
using log_handler_t = std::function<void(std::string)>;

/**
 * @brief Callback type for flush handlers.
 */
using flush_handler_t = std::function<void()>;

/**
 * @brief Callback type for close handlers.
 */
using close_handler_t = std::function<void()>;

/**
 * @brief Thread-safe logger that dispatches messages to per-level handlers.
 */
class Logger
{
  public:
    /**
     * @brief Creates a logger with the given callback handlers.
     * @param[in] log_handlers Array of log handler callbacks, one per log level
     *   (trace, debug, info, warning, error). Pass an empty callback for any level that is not needed.
     * @param[in] flush_handlers Array of flush handler callbacks, one per log level.
     * @param[in] close_handlers Array of close handler callbacks, one per log level.
     * @return A shared pointer to the new logger.
     */
    static std::shared_ptr<Logger> Create(std::array<log_handler_t, log_level_count> log_handlers,
                                          std::array<flush_handler_t, log_level_count> flush_handlers,
                                          std::array<close_handler_t, log_level_count> close_handlers)
    {
        return std::shared_ptr<Logger>(
            new Logger(std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers)));
    }

    ~Logger()
    {
        std::lock_guard<std::mutex> lock{mtx_};
        close_internal();
    }

    /**
     * @brief Flushes all log handlers on the logger.
     */
    void flush() const
    {
        std::lock_guard<std::mutex> lock{mtx_};
        flush_internal();
    }

    /**
     * @brief Closes all log handlers on the logger.
     * @note After closing, all handlers are reset to empty. The logger must be replaced via @ref GetOrSetLogger or @ref
     * ResetDefaultLogger before it can be used again.
     */
    void close()
    {
        std::lock_guard<std::mutex> lock{mtx_};
        close_internal();
    }

    /**
     * @brief Gets the current log level of the logger.
     * @return The current log level.
     */
    LogLevel get_level() const
    {
        std::lock_guard<std::mutex> lock{mtx_};
        return log_level_;
    }

    /**
     * @brief Sets the log level of the logger.
     * @param[in] level The new log level. Messages below this level are ignored.
     */
    void set_level(LogLevel level)
    {
        if (level > LogLevel::suppress)
        {
            level = LogLevel::suppress;
        }
        std::lock_guard<std::mutex> lock{mtx_};
        log_level_ = level;
    }

    /**
     * @brief Logs a message at the given level.
     * @param[in] level The log level for the message.
     * @param[in] msg The message string to log.
     */
    void log(LogLevel level, std::string msg) const;

    /**
     * @brief Logs a formatted message at the given level.
     * @param[in] level The log level for the message.
     * @param[in] fmt_str The format string.
     * @param[in] args The format arguments.
     */
    template <typename... Args> void log(LogLevel level, std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(level, std::format(fmt_str, std::forward<Args>(args)...));
    }

    /**
     * @brief Logs a formatted message at trace level.
     * @param[in] fmt_str The format string.
     * @param[in] args The format arguments.
     */
    template <typename... Args> void trace(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::trace, fmt_str, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs a formatted message at debug level.
     * @param[in] fmt_str The format string.
     * @param[in] args The format arguments.
     */
    template <typename... Args> void debug(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::debug, fmt_str, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs a formatted message at info level.
     * @param[in] fmt_str The format string.
     * @param[in] args The format arguments.
     */
    template <typename... Args> void info(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::info, fmt_str, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs a formatted message at warning level.
     * @param[in] fmt_str The format string.
     * @param[in] args The format arguments.
     */
    template <typename... Args> void warning(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::warning, fmt_str, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs a formatted message at error level.
     * @param[in] fmt_str The format string.
     * @param[in] args The format arguments.
     */
    template <typename... Args> void error(std::format_string<Args...> fmt_str, Args &&...args) const
    {
        log(LogLevel::error, fmt_str, std::forward<Args>(args)...);
    }

  private:
    Logger(std::array<log_handler_t, log_level_count> log_handlers,
           std::array<flush_handler_t, log_level_count> flush_handlers,
           std::array<close_handler_t, log_level_count> close_handlers)
        : log_handlers_{std::move(log_handlers)}, flush_handlers_{std::move(flush_handlers)},
          close_handlers_{std::move(close_handlers)} {};

    Logger(const Logger &) = delete;

    Logger &operator=(const Logger &) = delete;

    void flush_internal() const;

    void close_internal();

    mutable std::mutex mtx_;

    LogLevel log_level_ = LogLevel::info;

    std::array<log_handler_t, log_level_count> log_handlers_{};

    std::array<flush_handler_t, log_level_count> flush_handlers_{};

    std::array<close_handler_t, log_level_count> close_handlers_{};
};

/**
 * @brief Creates a new default stdout/stderr logger.
 * @return A shared pointer to the new default logger.
 */
std::shared_ptr<Logger> NewDefaultLogger();

/**
 * @brief Gets or replaces the global logger.
 * @param[in] new_logger If non-null, replaces the current global logger. If null, the current
 *   global logger is returned without replacing it.
 * @return The new global logger.
 */
std::shared_ptr<Logger> GetOrSetLogger(std::shared_ptr<Logger> new_logger);

/**
 * @brief Gets the current global logger.
 * @return A shared pointer to the global logger.
 */
inline std::shared_ptr<Logger> GetLogger()
{
    return GetOrSetLogger(nullptr);
}

/**
 * @brief Resets the global logger back to the default stdout/stderr logger.
 */
inline void ResetDefaultLogger()
{
    GetOrSetLogger(NewDefaultLogger());
}

} // namespace mpss
