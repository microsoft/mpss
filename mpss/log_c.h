// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Log level constants matching the C++ mpss::LogLevel enum.
     */
    typedef enum
    {
        MPSS_LOG_LEVEL_TRACE = 0,
        MPSS_LOG_LEVEL_DEBUG = 1,
        MPSS_LOG_LEVEL_INFO = 2,
        MPSS_LOG_LEVEL_WARN = 3,
        MPSS_LOG_LEVEL_ERR = 4,
        MPSS_LOG_LEVEL_SUPPRESS = 5,
    } mpss_log_level_t;

/**
 * @brief The number of actionable log levels (excludes SUPPRESS).
 */
#define MPSS_LOG_LEVEL_COUNT 5

    /**
     * @brief Callback type for log handlers.
     * @param message The log message string.
     */
    typedef void (*mpss_log_handler_t)(const char *message);

    /**
     * @brief Callback type for flush handlers.
     */
    typedef void (*mpss_flush_handler_t)(void);

    /**
     * @brief Callback type for close handlers.
     */
    typedef void (*mpss_close_handler_t)(void);

    /**
     * @brief Gets the current log level of the global logger.
     * @return The current log level.
     */
    MPSS_DECOR mpss_log_level_t mpss_log_get_level(void);

    /**
     * @brief Sets the log level of the global logger.
     * @param[in] level The new log level. Messages below this level are ignored.
     */
    MPSS_DECOR void mpss_log_set_level(mpss_log_level_t level);

    /**
     * @brief Logs a message at the given level using the global logger.
     * @param[in] level The log level for the message.
     * @param[in] message The message string to log.
     */
    MPSS_DECOR void mpss_log(mpss_log_level_t level, const char *message);

    /**
     * @brief Logs a message at TRACE level.
     * @param[in] message The message string to log.
     */
    MPSS_DECOR void mpss_log_trace(const char *message);

    /**
     * @brief Logs a message at DEBUG level.
     * @param[in] message The message string to log.
     */
    MPSS_DECOR void mpss_log_debug(const char *message);

    /**
     * @brief Logs a message at INFO level.
     * @param[in] message The message string to log.
     */
    MPSS_DECOR void mpss_log_info(const char *message);

    /**
     * @brief Logs a message at WARN level.
     * @param[in] message The message string to log.
     */
    MPSS_DECOR void mpss_log_warn(const char *message);

    /**
     * @brief Logs a message at ERR level.
     * @param[in] message The message string to log.
     */
    MPSS_DECOR void mpss_log_err(const char *message);

    /**
     * @brief Flushes all log handlers on the global logger.
     */
    MPSS_DECOR void mpss_log_flush(void);

    /**
     * @brief Closes all log handlers on the global logger.
     * @note After closing, all handlers are set to NULL. The logger must be reset with @ref mpss_log_reset_default or
     * @ref mpss_log_set_custom_logger before it can be used again.
     */
    MPSS_DECOR void mpss_log_close(void);

    /**
     * @brief Installs a custom logger with the given callback handlers.
     * @param[in] log_handlers Array of MPSS_LOG_LEVEL_COUNT log handler callbacks, one per log level
     *   (TRACE, DEBUG, INFO, WARN, ERR). Pass NULL for any callback that is not needed, or NULL
     *   for the entire array to leave log handlers empty.
     * @param[in] flush_handlers Array of MPSS_LOG_LEVEL_COUNT flush handler callbacks, one per log
     *   level. Pass NULL for any callback that is not needed, or NULL for the entire array.
     * @param[in] close_handlers Array of MPSS_LOG_LEVEL_COUNT close handler callbacks, one per log
     *   level. Pass NULL for any callback that is not needed, or NULL for the entire array.
     */
    MPSS_DECOR void mpss_log_set_custom_logger(mpss_log_handler_t log_handlers[MPSS_LOG_LEVEL_COUNT],
                                               mpss_flush_handler_t flush_handlers[MPSS_LOG_LEVEL_COUNT],
                                               mpss_close_handler_t close_handlers[MPSS_LOG_LEVEL_COUNT]);

    /**
     * @brief Resets the global logger back to the default stdout/stderr logger.
     */
    MPSS_DECOR void mpss_log_reset_default(void);

#ifdef __cplusplus
} // extern "C"
#endif
