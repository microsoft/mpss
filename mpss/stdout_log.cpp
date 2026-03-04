// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/log.h"
#include <iostream>

namespace mpss
{

using enum LogLevel;

std::shared_ptr<Logger> NewDefaultLogger()
{
    std::array<log_handler_t, log_level_count> log_handlers{};
    log_handlers[static_cast<std::size_t>(trace)] = [](std::string msg) { std::cout << "[trace] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(debug)] = [](std::string msg) { std::cout << "[debug] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(info)] = [](std::string msg) { std::cout << "[info] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(warning)] = [](std::string msg) { std::cerr << "[warning] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(error)] = [](std::string msg) { std::cerr << "[error] " << msg << '\n'; };

    std::array<flush_handler_t, log_level_count> flush_handlers{};
    flush_handlers[static_cast<std::size_t>(trace)] = []() { std::cout << std::flush; };
    flush_handlers[static_cast<std::size_t>(debug)] = []() { std::cout << std::flush; };
    flush_handlers[static_cast<std::size_t>(info)] = []() { std::cout << std::flush; };
    flush_handlers[static_cast<std::size_t>(warning)] = []() { std::cerr << std::flush; };
    flush_handlers[static_cast<std::size_t>(error)] = []() { std::cerr << std::flush; };

    // No special close actions needed for stdout/stderr.
    std::array<close_handler_t, log_level_count> close_handlers{};

    return Logger::Create(std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers));
}

} // namespace mpss
