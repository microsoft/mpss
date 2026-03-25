// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// Platform-compatible wrappers for setenv / unsetenv.
// MSVC does not provide the POSIX versions; _putenv_s is the equivalent.

#if defined(_WIN32) && defined(_MSC_VER)
#include <cerrno>
#include <cstdlib>
#include <cstring>

inline int setenv(const char *name, const char *value, int overwrite) noexcept
{
    if (nullptr == name || '\0' == name[0] || nullptr != std::strchr(name, '=') || nullptr == value)
    {
        errno = EINVAL;
        return -1;
    }
    if (0 == overwrite)
    {
        size_t len = 0;
        if (0 == getenv_s(&len, nullptr, 0, name) && len > 0)
        {
            return 0;
        }
    }
    const errno_t err = _putenv_s(name, value);
    if (0 != err)
    {
        errno = err;
        return -1;
    }
    return 0;
}

inline int unsetenv(const char *name) noexcept
{
    if (nullptr == name || '\0' == name[0] || nullptr != std::strchr(name, '='))
    {
        errno = EINVAL;
        return -1;
    }
    const errno_t err = _putenv_s(name, "");
    if (0 != err)
    {
        errno = err;
        return -1;
    }
    return 0;
}
#endif // _WIN32 && _MSC_VER
