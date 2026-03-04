// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/interaction_handler.h"
#include "mpss/secure_types.h"
#include <cstdlib>
#include <iostream>
#include <optional>

#ifdef _WIN32
#include <Windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace
{

/**
 * @brief Read a line from stdin with echo disabled, directly into a SecureString.
 * @return The line read, or std::nullopt if stdin is not a terminal or an error occurred.
 */
std::optional<mpss::SecureString> read_secure_line()
{
#ifdef _WIN32
    const HANDLE h_stdin = GetStdHandle(STD_INPUT_HANDLE);
    if (INVALID_HANDLE_VALUE == h_stdin)
    {
        return std::nullopt;
    }

    DWORD mode = 0;
    if (!GetConsoleMode(h_stdin, &mode))
    {
        // Not a console (e.g., piped input).
        return std::nullopt;
    }

    // Disable echo.
    const DWORD saved_mode = mode;
    mode &= ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(h_stdin, mode))
    {
        return std::nullopt;
    }

    mpss::SecureString line;
    if (!std::getline(std::cin, line))
    {
        SetConsoleMode(h_stdin, saved_mode);
        return std::nullopt;
    }

    // Restore echo.
    SetConsoleMode(h_stdin, saved_mode);
    return line;
#elif defined(__unix__) || defined(__APPLE__)
    if (0 == isatty(STDIN_FILENO))
    {
        // Not a terminal (e.g., piped input).
        return std::nullopt;
    }

    struct termios old_attrs{};
    if (0 != tcgetattr(STDIN_FILENO, &old_attrs))
    {
        return std::nullopt;
    }

    // Disable echo.
    struct termios new_attrs = old_attrs;
    new_attrs.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    if (0 != tcsetattr(STDIN_FILENO, TCSANOW, &new_attrs))
    {
        return std::nullopt;
    }

    mpss::SecureString line;
    if (!std::getline(std::cin, line))
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_attrs);
        return std::nullopt;
    }

    // Restore echo.
    tcsetattr(STDIN_FILENO, TCSANOW, &old_attrs);
    return line;
#endif
}

/**
 * @brief A simple terminal-based interaction handler.
 *
 * Checks the MPSS_YUBIKEY_PIN environment variable first. If not set, prompts the user on the terminal with echo
 * disabled. Other implementations may choose to ignore MPSS_YUBIKEY_PIN and always prompt, or to provide a GUI
 * dialog instead of a terminal prompt.
 */
class TerminalInteractionHandler : public mpss::InteractionHandler
{
  public:
    [[nodiscard]] std::optional<mpss::SecureString> request_pin(std::string_view context) override
    {
        // Check environment variable first.
        const char *env_pin = std::getenv("MPSS_YUBIKEY_PIN");
        if (nullptr != env_pin && '\0' != env_pin[0])
        {
            return mpss::SecureString{env_pin};
        }

        // Prompt on terminal.
        std::cerr << "Enter YubiKey PIN (" << context << "): " << std::flush;
        auto pin = read_secure_line();
#ifndef _WIN32
        // On Unix, echo is disabled via termios and Enter does not produce visible output.
        // On Windows, the console still outputs a newline for Enter even with echo disabled.
        std::cerr << '\n';
#endif
        return pin;
    }

    void notify_touch_needed() override
    {
        std::cerr << "Touch your YubiKey now ... " << std::flush;
    }

    void notify_touch_complete() override
    {
        std::cerr << "done." << std::endl;
    }
};

} // namespace

namespace mpss
{

std::shared_ptr<InteractionHandler> NewDefaultInteractionHandler()
{
    return std::make_shared<TerminalInteractionHandler>();
}

} // namespace mpss